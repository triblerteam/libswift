/*
 *  cmdgw.cpp
 *  command gateway for controling swift engine via a TCP connection
 *
 *  Created by Arno Bakker
 *  Copyright 2010-2012 TECHNISCHE UNIVERSITEIT DELFT. All rights reserved.
 *
 */
#include <math.h>
#include <iostream>
#include <sstream>

#include "swift.h"
#include "compat.h"
#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/listener.h>


using namespace swift;

// Send PLAY after receiving 2^layer * chunksize bytes
#define CMDGW_MAX_PREBUF_BYTES		(256*1024)


// Status of the swarm download
#define DLSTATUS_HASHCHECKING  2
#define DLSTATUS_DOWNLOADING  3
#define DLSTATUS_SEEDING 4

#define MAX_CMD_MESSAGE 1024

#define ERROR_NO_ERROR		0
#define ERROR_UNKNOWN_CMD	-1
#define ERROR_MISS_ARG		-2
#define ERROR_BAD_ARG		-3

#define CMDGW_MAX_CLIENT 1024   // Arno: == maximum number of swarms per proc

struct cmd_gw_t {
    int      id;
    evutil_socket_t   cmdsock;
    int		 transfer; // swift FD
    char 	*contentfilename; // basename of content file
    bool	moreinfo;		  // whether to report detailed stats (see SETMOREINFO cmd)
    tint 	startt;			  // ARNOSMPTODO: debug speed measurements, remove
} cmd_requests[CMDGW_MAX_CLIENT];


int cmd_gw_reqs_open = 0;
int cmd_gw_reqs_count = 0;

struct evconnlistener *cmd_evlistener = NULL;
struct evbuffer *cmd_evbuffer = NULL; // Data received on cmd socket : WARNING: one for all cmd sockets

/*
 * SOCKTUNNEL
 * We added the ability for a process to tunnel data over swift's UDP socket.
 * The process should send TUNNELSEND commands over the CMD TCP socket and will
 * receive TUNNELRECV commands from swift, containing data received via UDP
 * on channel 0xffffffff.
 */
typedef enum {
	CMDGW_TUNNEL_SCAN4CRLF,
	CMDGW_TUNNEL_READTUNNEL
} cmdgw_tunnel_t;

cmdgw_tunnel_t cmd_tunnel_state=CMDGW_TUNNEL_SCAN4CRLF;
uint32_t	 cmd_tunnel_expect=0;
Address		 cmd_tunnel_dest_addr;
evutil_socket_t   cmd_tunnel_sock=INVALID_SOCKET;

// HTTP gateway address for PLAY cmd
Address cmd_gw_httpaddr;


bool cmd_gw_debug=false;


// Fwd defs
void CmdGwDataCameInCallback(struct bufferevent *bev, void *ctx);
bool CmdGwReadLine(evutil_socket_t cmdsock);
void CmdGwNewRequestCallback(evutil_socket_t cmdsock, char *line);
void CmdGwProcessData(evutil_socket_t cmdsock);


void CmdGwFreeRequest(cmd_gw_t* req)
{
    if (req->contentfilename != NULL)
        free(req->contentfilename);
    // Arno, 2012-02-06: Reset, in particular moreinfo flag.
    memset(req,'\0',sizeof(cmd_gw_t));
}


void CmdGwCloseConnection(evutil_socket_t sock)
{
	// Close cmd connection and stop all associated downloads.
	// Doesn't remove .mhash state or content

	bool scanning = true;
	while (scanning)
	{
		scanning = false;
	    for(int i=0; i<cmd_gw_reqs_open; i++)
	    {
	    	cmd_gw_t* req = &cmd_requests[i];
	        if (req->cmdsock==sock)
	        {
                dprintf("%s @%i stopping-on-close transfer %i\n",tintstr(),req->id,req->transfer);
                swift::Close(req->transfer);

                // Remove from list and reiterate over it
                CmdGwFreeRequest(req);
	        	*req = cmd_requests[--cmd_gw_reqs_open];
	        	scanning = true;
	        	break;
	        }
	    }
	}
}


cmd_gw_t* CmdGwFindRequestByTransfer (int transfer)
{
    for(int i=0; i<cmd_gw_reqs_open; i++)
        if (cmd_requests[i].transfer==transfer)
            return cmd_requests+i;
    return NULL;
}

cmd_gw_t* CmdGwFindRequestByRootHash(Sha1Hash &want_hash)
{
	FileTransfer *ft = NULL;
    for(int i=0; i<cmd_gw_reqs_open; i++) {
    	cmd_gw_t* req = &cmd_requests[i];
    	ft = FileTransfer::file(req->transfer);
    	Sha1Hash got_hash = ft->root_hash();
        if (want_hash == got_hash)
        	return req;
    }
    return NULL;
}


void CmdGwGotCHECKPOINT(Sha1Hash &want_hash)
{
	// Checkpoint the specified download
	fprintf(stderr,"cmd: GotCHECKPOINT: %s\n",want_hash.hex().c_str());

	cmd_gw_t* req = CmdGwFindRequestByRootHash(want_hash);
	if (req == NULL)
    	return;
    FileTransfer *ft = FileTransfer::file(req->transfer);

	std::string binmap_filename = ft->file().filename();
	binmap_filename.append(".mbinmap");
	fprintf(stderr,"cmdgw: GotCHECKPOINT: checkpointing to %s\n", binmap_filename.c_str() );
	FILE *fp = fopen(binmap_filename.c_str(),"wb");
	if (!fp) {
		print_error("cannot open mbinmap for writing");
		return;
	}
	if (ft->file().serialize(fp) < 0)
		print_error("writing to mbinmap");
	fclose(fp);
}


void CmdGwGotREMOVE(Sha1Hash &want_hash, bool removestate, bool removecontent)
{
	// Remove the specified download
	fprintf(stderr,"cmd: GotREMOVE: %s %d %d\n",want_hash.hex().c_str(),removestate,removecontent);

	cmd_gw_t* req = CmdGwFindRequestByRootHash(want_hash);
	if (req == NULL)
    	return;
    FileTransfer *ft = FileTransfer::file(req->transfer);

	fprintf(stderr, "%s @%i remove transfer %i\n",tintstr(),req->id,req->transfer);
	dprintf("%s @%i remove transfer %i\n",tintstr(),req->id,req->transfer);
	swift::Close(req->transfer);

	// Delete content + .mhash from filesystem, if desired
	if (removecontent)
		remove(req->contentfilename);

	if (removestate)
	{
		char *mhashfilename = (char *)malloc(strlen(req->contentfilename)+strlen(".mhash")+1);
		strcpy(mhashfilename,req->contentfilename);
		strcat(mhashfilename,".mhash");

		remove(mhashfilename);
		free(mhashfilename);

		// Arno, 2012-01-10: .mbinmap gots to go too.
		char *mbinmapfilename = (char *)malloc(strlen(req->contentfilename)+strlen(".mbinmap")+1);
		strcpy(mbinmapfilename,req->contentfilename);
		strcat(mbinmapfilename,".mbinmap");

		remove(mbinmapfilename);
		free(mbinmapfilename);
	}

	CmdGwFreeRequest(req);
	*req = cmd_requests[--cmd_gw_reqs_open];
}


void CmdGwGotMAXSPEED(Sha1Hash &want_hash, data_direction_t ddir, double speed)
{
	// Set maximum speed on the specified download
	fprintf(stderr,"cmd: GotMAXSPEED: %s %d %lf\n",want_hash.hex().c_str(),ddir,speed);

	cmd_gw_t* req = CmdGwFindRequestByRootHash(want_hash);
	if (req == NULL)
    	return;
    FileTransfer *ft = FileTransfer::file(req->transfer);
	ft->SetMaxSpeed(ddir,speed);
}


void CmdGwGotSETMOREINFO(Sha1Hash &want_hash, bool enable)
{
	cmd_gw_t* req = CmdGwFindRequestByRootHash(want_hash);
	if (req == NULL)
    	return;
	req->moreinfo = enable;
}


void CmdGwSendINFOHashChecking(cmd_gw_t* req, Sha1Hash root_hash)
{
	// Send INFO DLSTATUS_HASHCHECKING message.

    char cmd[MAX_CMD_MESSAGE];
	sprintf(cmd,"INFO %s %d %lli/%lli %lf %lf %u %u\r\n",root_hash.hex().c_str(),DLSTATUS_HASHCHECKING,(uint64_t)0,(uint64_t)0,0.0,0.0,0,0);

    //fprintf(stderr,"cmd: SendINFO: %s", cmd);
    send(req->cmdsock,cmd,strlen(cmd),0);
}


void CmdGwSendINFO(cmd_gw_t* req, int dlstatus)
{
	// Send INFO message.
	if (cmd_gw_debug)
		fprintf(stderr,"cmd: SendINFO: %d %d\n", req->transfer, dlstatus );

	FileTransfer *ft = FileTransfer::file(req->transfer);
	if (ft == NULL)
		// Download was removed or closed somehow.
		return;

    Sha1Hash root_hash = ft->root_hash();

    char cmd[MAX_CMD_MESSAGE];
    uint64_t size = swift::Size(req->transfer);
    uint64_t complete = swift::Complete(req->transfer);
    if (size == complete)
    	dlstatus = DLSTATUS_SEEDING;

    uint32_t numleech = ft->GetNumLeechers();
    uint32_t numseeds = ft->GetNumSeeders();
    sprintf(cmd,"INFO %s %d %lli/%lli %lf %lf %u %u\r\n",root_hash.hex().c_str(),dlstatus,complete,size,ft->GetCurrentSpeed(DDIR_DOWNLOAD),ft->GetCurrentSpeed(DDIR_UPLOAD),numleech,numseeds);

    //fprintf(stderr,"cmd: SendINFO: %s", cmd);
    send(req->cmdsock,cmd,strlen(cmd),0);

    // MORESTATS
    if (req->moreinfo) {
    	// Send detailed ul/dl stats in JSON format.

    	std::ostringstream oss;
    	oss.setf(std::ios::fixed,std::ios::floatfield);
    	oss.precision(5);
        std::set<Channel *>::iterator iter;
        std::set<Channel *> peerchans = ft->GetChannels();

        oss << "MOREINFO" << " " << root_hash.hex() << " ";

        double tss = (double)Channel::Time() / 1000000.0L;
        oss << "{\"timestamp\":\"" << tss << "\", ";
        oss << "\"channels\":";
        oss << "[";
        for (iter=peerchans.begin(); iter!=peerchans.end(); iter++) {
    		Channel *c = *iter;
    		if (c != NULL) {
    			if (iter!=peerchans.begin())
    				oss << ", ";
    			oss << "{";
    			oss << "\"ip\": \"" << c->peer().ipv4str() << "\", ";
    			oss << "\"port\": " << c->peer().port() << ", ";
    			oss << "\"raw_bytes_up\": " << c->raw_bytes_up() << ", ";
    			oss << "\"raw_bytes_down\": " << c->raw_bytes_down() << ", ";
    			oss << "\"bytes_up\": " << c->bytes_up() << ", ";
    			oss << "\"bytes_down\": " << c->bytes_down() << " ";
    			oss << "}";
    		}
        }
        oss << "], ";
        oss << "\"raw_bytes_up\": " << Channel::global_raw_bytes_up << ", ";
        oss << "\"raw_bytes_down\": " << Channel::global_raw_bytes_down << ", ";
        oss << "\"bytes_up\": " << Channel::global_bytes_up << ", ";
        oss << "\"bytes_down\": " << Channel::global_bytes_down << " ";
        oss << "}";

        oss << "\r\n";

        std::stringbuf *pbuf=oss.rdbuf();
        size_t slen = strlen(pbuf->str().c_str());
        send(req->cmdsock,pbuf->str().c_str(),slen,0);
    }
}


void CmdGwSendPLAY(int transfer)
{
	// Send PLAY message to user
	if (cmd_gw_debug)
		fprintf(stderr,"cmd: SendPLAY: %d\n", transfer );

    cmd_gw_t* req = CmdGwFindRequestByTransfer(transfer);
    Sha1Hash root_hash = FileTransfer::file(transfer)->root_hash();

    char cmd[MAX_CMD_MESSAGE];
    // Slightly diff format: roothash as ID after CMD
    sprintf(cmd,"PLAY %s http://%s/%s\r\n",root_hash.hex().c_str(),cmd_gw_httpaddr.str(),root_hash.hex().c_str());

    fprintf(stderr,"cmd: SendPlay: %s", cmd);

    send(req->cmdsock,cmd,strlen(cmd),0);
}


void CmdGwSwiftFirstProgressCallback (int transfer, bin_t bin)
{
	// First CMDGW_MAX_PREBUF_BYTES bytes received via swift,
	// tell user to PLAY
	// ARNOSMPTODO: bitrate-dependent prebuffering?
	if (cmd_gw_debug)
		fprintf(stderr,"cmd: SwiftFirstProgress: %d\n", transfer );

	swift::RemoveProgressCallback(transfer,&CmdGwSwiftFirstProgressCallback);

	CmdGwSendPLAY(transfer);
}


void CmdGwSwiftErrorCallback (evutil_socket_t cmdsock)
{
	// Error on swift socket callback

	const char *response = "ERROR Swift Engine Problem\r\n";
	send(cmdsock,response,strlen(response),0);

	//swift::close_socket(sock);
}



void CmdGwUpdateDLStateCallback(cmd_gw_t* req)
{
	// Periodic callback, tell user INFO
	CmdGwSendINFO(req,DLSTATUS_DOWNLOADING);

	// Update speed measurements such that they decrease when DL/UL stops
	FileTransfer *ft = FileTransfer::file(req->transfer);
	ft->OnRecvData(0);
	ft->OnSendData(0);

	if (false)
	{
		// DEBUG download speed rate limit
		double dlspeed = ft->GetCurrentSpeed(DDIR_DOWNLOAD);
#ifdef WIN32
		double dt = max(0.000001,(double)(usec_time() - req->startt)/TINT_SEC);
#else
		double dt = std::max(0.000001,(double)(usec_time() - req->startt)/TINT_SEC);
#endif
		double exspeed = (double)(swift::Complete(req->transfer)) / dt;
		fprintf(stderr,"cmd: UpdateDLStateCallback: SPEED %lf == %lf\n", dlspeed, exspeed );
	}
}


void CmdGwUpdateDLStatesCallback()
{
	// Called by swift main approximately every second
	// Loop over all swarms
    for(int i=0; i<cmd_gw_reqs_open; i++)
    {
    	cmd_gw_t* req = &cmd_requests[i];
    	CmdGwUpdateDLStateCallback(req);
    }
}



void CmdGwDataCameInCallback(struct bufferevent *bev, void *ctx)
{
	// Turn TCP stream into lines deliniated by \r\n

	evutil_socket_t cmdsock = bufferevent_getfd(bev);
	if (cmd_gw_debug)
		fprintf(stderr,"CmdGwDataCameIn: ENTER %d\n", cmdsock );

	struct evbuffer *inputevbuf = bufferevent_get_input(bev);

	int inlen = evbuffer_get_length(inputevbuf);

    int ret = evbuffer_add_buffer(cmd_evbuffer,inputevbuf);
	if (ret == -1) {
		CmdGwCloseConnection(cmdsock);
		return;
	}

	int totlen = evbuffer_get_length(cmd_evbuffer);

	if (cmd_gw_debug)
		fprintf(stderr,"cmdgw: TCPDataCameIn: State %d, got %d new bytes, have %d want %d\n", (int)cmd_tunnel_state, inlen, totlen, cmd_tunnel_expect );

	CmdGwProcessData(cmdsock);
}


void CmdGwProcessData(evutil_socket_t cmdsock)
{
	// Process CMD data in the cmd_evbuffer

	if (cmd_tunnel_state == CMDGW_TUNNEL_SCAN4CRLF)
	{
		bool ok=false;
		do
		{
			ok = CmdGwReadLine(cmdsock);
			if (ok && cmd_tunnel_state == CMDGW_TUNNEL_READTUNNEL)
				break;
		} while (ok);
	}
	// Not else!
	if (cmd_tunnel_state == CMDGW_TUNNEL_READTUNNEL)
	{
		// Got "TUNNELSEND addr size\r\n" command, now read
		// size bytes, i.e., cmd_tunnel_expect bytes.

		if (cmd_gw_debug)
			fprintf(stderr,"cmdgw: procTCPdata: tunnel state, got %d, want %d\n", evbuffer_get_length(cmd_evbuffer), cmd_tunnel_expect );

		if (evbuffer_get_length(cmd_evbuffer) >= cmd_tunnel_expect)
		{
			// We have all the tunneled data
			CmdGwTunnelSendUDP(cmd_evbuffer);

			// Process any remaining commands that came after the tunneled data
			CmdGwProcessData(cmdsock);
		}
	}
}


bool CmdGwReadLine(evutil_socket_t cmdsock)
{
	// Parse cmd_evbuffer for lines, and call NewRequest when found

	size_t rd=0;
    char *cmd = evbuffer_readln(cmd_evbuffer,&rd, EVBUFFER_EOL_CRLF_STRICT);
    if (cmd != NULL)
    {
    	CmdGwNewRequestCallback(cmdsock,cmd);
    	free(cmd);
    	return true;
    }
    else
    	return false;
}

int CmdGwHandleCommand(evutil_socket_t cmdsock, char *copyline);

void CmdGwNewRequestCallback(evutil_socket_t cmdsock, char *line)
{
	// New command received from user

    // CMD request line
	char *copyline = (char *)malloc(strlen(line)+1);
	strcpy(copyline,line);

	int ret = CmdGwHandleCommand(cmdsock,copyline);
	if (ret < 0) {
		dprintf("cmd: Error parsing command %s\n", line );
		char *cmd = NULL;
		if (ret == ERROR_UNKNOWN_CMD)
			cmd = "ERROR unknown command\r\n";
		else if (ret == ERROR_MISS_ARG)
			cmd = "ERROR missing parameter\r\n";
		else
			cmd = "ERROR bad parameter\r\n";
		send(cmdsock,cmd,strlen(cmd),0);
        CmdGwCloseConnection(cmdsock);
	}

    free(copyline);
}


int CmdGwHandleCommand(evutil_socket_t cmdsock, char *copyline)
{
	char *method=NULL,*paramstr = NULL;
	char * token = strchr(copyline,' '); // split into CMD PARAM
	if (token != NULL) {
		*token = '\0';
		paramstr = token+1;
	}
	else
		paramstr = "";

	method = copyline;

    fprintf(stderr,"cmd: GOT %s %s\n", method, paramstr);

    char *savetok = NULL;
    if (!strcmp(method,"START"))
    {
    	// New START request
        cmd_gw_t* req = cmd_requests + cmd_gw_reqs_open++;
        req->id = ++cmd_gw_reqs_count;
        req->cmdsock = cmdsock;

        //fprintf(stderr,"cmd: START: new request %i\n",req->id);

    	char *url = paramstr;
        // parse URL
		// tswift://tracker/roothash-as-hex$chunksize@duration-in-secs
        char *trackerstr=NULL,*hashstr=NULL,*durationstr=NULL,*chunksizestr=NULL;

        bool haschunksize = (bool)(strchr(paramstr,'$') != NULL);
        bool hasduration = (bool)(strchr(paramstr,'@') != NULL); // FAXME: user@ in tracker URL

        token = strtok_r(url,"/",&savetok); // tswift://
        if (token == NULL)
        	return ERROR_MISS_ARG;
        token = strtok_r(NULL,"/",&savetok);      // tracker:port
        if (token == NULL)
        	return ERROR_MISS_ARG;
        trackerstr = token;

        if (haschunksize && hasduration) {
        	token = strtok_r(NULL,"$",&savetok);       // roothash
        	if (token == NULL)
        		return ERROR_BAD_ARG;
        	hashstr = token;

            token = strtok_r(NULL,"@",&savetok);			// chunksize
            if (token == NULL)
                return ERROR_BAD_ARG;
            chunksizestr = token;

        	token = strtok_r(NULL,"",&savetok);		// duration
        	if (token == NULL)
        		return ERROR_BAD_ARG;
        	durationstr = token;
        }
        else if (haschunksize) {
        	token = strtok_r(NULL,"$",&savetok);       // roothash
        	if (token == NULL)
        		return ERROR_BAD_ARG;
        	hashstr = token;

            token = strtok_r(NULL,"",&savetok);			// chunksize
            if (token == NULL)
                	return ERROR_BAD_ARG;
            chunksizestr = token;
        }
        else if (hasduration) {
        	token = strtok_r(NULL,"@",&savetok);       // roothash
        	if (token == NULL)
        		return ERROR_BAD_ARG;
        	hashstr = token;

            token = strtok_r(NULL,"",&savetok);			// duration
            if (token == NULL)
                	return ERROR_BAD_ARG;
            durationstr = token;
        }
        else {
        	token = strtok_r(NULL,"",&savetok);       // roothash
        	if (token == NULL)
        		return ERROR_BAD_ARG;
        	hashstr = token;
        }

        dprintf("cmd: START: parsed tracker %s hash %s dur %s cs %s\n",trackerstr,hashstr,durationstr,chunksizestr);

        if (strlen(hashstr)!=40) {
        	dprintf("cmd: START: roothash too short %i\n", strlen(hashstr) );
            return ERROR_BAD_ARG;
        }
        size_t chunksize=SWIFT_DEFAULT_CHUNK_SIZE;
        if (haschunksize) {
        	int n = sscanf(chunksizestr,"%i",&chunksize);
        	if (n != 1)
        		return ERROR_BAD_ARG;
        }
        int duration=0;
        if (hasduration) {
        	int n = sscanf(durationstr,"%i",&duration);
        	if (n != 1)
        		return ERROR_BAD_ARG;
        }

        dprintf("cmd: START: %s with tracker %s chunksize %i duration %i\n",hashstr,trackerstr,chunksize,duration);

        // FAXME: return duration in HTTPGW

        Address trackaddr;
		trackaddr = Address(trackerstr);
		if (trackaddr==Address())
		{
			dprintf("cmd: START: tracker address must be hostname:port, ip:port or just port\n");
	        return ERROR_BAD_ARG;
		}
		// SetTracker(trackaddr); == set default tracker

        // initiate transmission
        Sha1Hash root_hash = Sha1Hash(true,hashstr);

        // Send INFO DLSTATUS_HASHCHECKING
		CmdGwSendINFOHashChecking(req,root_hash);

		// ARNOSMPTODO: disable/interleave hashchecking at startup
        int transfer = swift::Find(root_hash);
        if (transfer==-1)
            transfer = swift::Open(hashstr,root_hash,trackaddr,false,chunksize);

        // RATELIMIT
        //FileTransfer::file(transfer)->SetMaxSpeed(DDIR_DOWNLOAD,512*1024);

        req->transfer = transfer;
        req->startt = usec_time();

        // See HashTree::HashTree
        req->contentfilename = (char *)malloc(strlen(hashstr)+1);
        strcpy(req->contentfilename,hashstr);

        if (cmd_gw_debug)
        	fprintf(stderr,"cmd: Already on disk is %lli/%lli\n", swift::Complete(transfer), swift::Size(transfer));

        // Wait for prebuffering and then send PLAY to user
    	// ARNOSMPTODO: OUTOFORDER: breaks with out-of-order download
        if (swift::Size(transfer) >= CMDGW_MAX_PREBUF_BYTES)
        {
            CmdGwSwiftFirstProgressCallback(transfer,bin_t(0,0));
            CmdGwSendINFO(req, DLSTATUS_DOWNLOADING);
        }
        else
        {
        	int progresslayer = bytes2layer(CMDGW_MAX_PREBUF_BYTES,swift::ChunkSize(transfer));
            swift::AddProgressCallback(transfer,&CmdGwSwiftFirstProgressCallback,progresslayer);
        }
    }
    else if (!strcmp(method,"REMOVE"))
    {
    	// REMOVE roothash removestate removecontent\r\n
    	bool removestate = false, removecontent = false;

        token = strtok_r(paramstr," ",&savetok); //
        if (token == NULL)
        	return ERROR_MISS_ARG;
        char *hashstr = token;
        token = strtok_r(NULL," ",&savetok);      // removestate
        if (token == NULL)
        	return ERROR_MISS_ARG;
        removestate = !strcmp(token,"1");
        token = strtok_r(NULL,"",&savetok);       // removecontent
        if (token == NULL)
        	return ERROR_MISS_ARG;
        removecontent = !strcmp(token,"1");

    	Sha1Hash root_hash = Sha1Hash(true,hashstr);
    	CmdGwGotREMOVE(root_hash,removestate,removecontent);
    }
    else if (!strcmp(method,"MAXSPEED"))
    {
    	// MAXSPEED roothash direction speed-float-kb/s\r\n
    	data_direction_t ddir;
    	double speed;

        token = strtok_r(paramstr," ",&savetok); //
        if (token == NULL)
        	return ERROR_MISS_ARG;
        char *hashstr = token;
        token = strtok_r(NULL," ",&savetok);      // direction
        if (token == NULL)
        	return ERROR_MISS_ARG;
        ddir = !strcmp(token,"DOWNLOAD") ? DDIR_DOWNLOAD : DDIR_UPLOAD;
        token = strtok_r(NULL,"",&savetok);       // speed
        if (token == NULL)
        	return ERROR_MISS_ARG;
        int n = sscanf(token,"%lf",&speed);
        if (n == 0) {
        	dprintf("cmd: MAXSPEED: speed is not a float\n");
			return ERROR_MISS_ARG;
        }
    	Sha1Hash root_hash = Sha1Hash(true,hashstr);
    	CmdGwGotMAXSPEED(root_hash,ddir,speed*1024.0);
    }
    else if (!strcmp(method,"CHECKPOINT"))
    {
    	// CHECKPOINT roothash\r\n
    	Sha1Hash root_hash = Sha1Hash(true,paramstr);
    	CmdGwGotCHECKPOINT(root_hash);
    }
    else if (!strcmp(method,"SETMOREINFO"))
    {
    	// GETMOREINFO roothash toggle\r\n
        token = strtok_r(paramstr," ",&savetok); // hash
        if (token == NULL)
        	return ERROR_MISS_ARG;
        char *hashstr = token;
        token = strtok_r(NULL," ",&savetok);      // bool
        if (token == NULL)
        	return ERROR_MISS_ARG;
        bool enable = (bool)!strcmp(token,"1");
    	Sha1Hash root_hash = Sha1Hash(true,hashstr);
    	CmdGwGotSETMOREINFO(root_hash,enable);
    }
    else if (!strcmp(method,"SHUTDOWN"))
    {
    	CmdGwCloseConnection(cmdsock);
    	// Tell libevent to stop processing events
    	event_base_loopexit(Channel::evbase, NULL);
    }
    else if (!strcmp(method,"TUNNELSEND"))
    {
        token = strtok_r(paramstr," ",&savetok); // dest addr
        if (token == NULL)
        	return ERROR_MISS_ARG;
        char *addrstr = token;
        token = strtok_r(NULL," ",&savetok);      // size
        if (token == NULL)
        	return ERROR_MISS_ARG;
        char *sizestr = token;

    	cmd_tunnel_dest_addr = Address(addrstr);
    	int n = sscanf(sizestr,"%u",&cmd_tunnel_expect);
    	if (n != 1)
    		return ERROR_BAD_ARG;

        cmd_tunnel_state = CMDGW_TUNNEL_READTUNNEL;

        if (cmd_gw_debug)
        	fprintf(stderr,"cmdgw: Want tunnel %d bytes to %s\n", cmd_tunnel_expect, cmd_tunnel_dest_addr.str() );
    }
    else
    {
    	return ERROR_UNKNOWN_CMD;
    }

    return ERROR_NO_ERROR;
}



void CmdGwEventCameInCallback(struct bufferevent *bev, short events, void *ctx)
{
	if (events & BEV_EVENT_ERROR)
		print_error("cmdgw: Error from bufferevent");
    if (events & (BEV_EVENT_EOF | BEV_EVENT_ERROR))
    {
    	// Called when error on cmd connection
    	evutil_socket_t cmdsock = bufferevent_getfd(bev);
    	CmdGwCloseConnection(cmdsock);
		bufferevent_free(bev);
    }
}


void CmdGwNewConnectionCallback(struct evconnlistener *listener,
    evutil_socket_t fd, struct sockaddr *address, int socklen,
    void *ctx)
{
	// New TCP connection on cmd listen socket

	fprintf(stderr,"cmd: Got new cmd connection %i\n",fd);

	struct event_base *base = evconnlistener_get_base(listener);
	struct bufferevent *bev = bufferevent_socket_new(base, fd, BEV_OPT_CLOSE_ON_FREE);

	bufferevent_setcb(bev, CmdGwDataCameInCallback, NULL, CmdGwEventCameInCallback, NULL);
	bufferevent_enable(bev, EV_READ|EV_WRITE);


	// One buffer for all cmd connections, reset
	if (cmd_evbuffer != NULL)
		evbuffer_free(cmd_evbuffer);
    cmd_evbuffer = evbuffer_new();

    // SOCKTUNNEL: assume 1 command connection
    cmd_tunnel_sock = fd;
}


void CmdGwListenErrorCallback(struct evconnlistener *listener, void *ctx)
{
	// libevent got error on cmd listener
    struct event_base *base = evconnlistener_get_base(listener);
    int err = EVUTIL_SOCKET_ERROR();
    char errmsg[1024];
    sprintf(errmsg, "cmdgw: Got a fatal error %d (%s) on the listener.\n", err, evutil_socket_error_to_string(err));

    print_error(errmsg);
    dprintf("%s @0 closed cmd gateway\n",tintstr());

	evconnlistener_free(cmd_evlistener);
}


bool InstallCmdGateway (struct event_base *evbase,Address cmdaddr,Address httpaddr)
{
	// Allocate libevent listener for cmd connections
	// From http://www.wangafu.net/~nickm/libevent-book/Ref8_listener.html

    fprintf(stderr,"cmdgw: Creating new TCP listener on addr %s\n", cmdaddr.str() );
  
    const struct sockaddr_in sin = (sockaddr_in)cmdaddr;

    cmd_evlistener = evconnlistener_new_bind(evbase, CmdGwNewConnectionCallback, NULL,
        LEV_OPT_CLOSE_ON_FREE|LEV_OPT_REUSEABLE, -1,
        (const struct sockaddr *)&sin, sizeof(sin));
    if (!cmd_evlistener) {
            print_error("Couldn't create listener");
            return false;
    }
    evconnlistener_set_error_cb(cmd_evlistener, CmdGwListenErrorCallback);

    cmd_gw_httpaddr = httpaddr;

    cmd_evbuffer = evbuffer_new();

    return true;
}



// SOCKTUNNEL
void swift::CmdGwTunnelUDPDataCameIn(Address src, struct evbuffer* evb)
{
	// Message received on UDP socket, forward over TCP conn.

	if (cmd_gw_debug)
		fprintf(stderr,"cmdgw: TunnelUDPData:DataCameIn %d bytes from %s\n", evbuffer_get_length(evb), src.str() );

	/*
	 *  Format:
	 *  TUNNELRECV addr nbytes\r\n
	 *  <bytes>
	 */

    std::ostringstream oss;
    oss << "TUNNELRECV " << src.str();
    oss << " " << evbuffer_get_length(evb) << "\r\n";

	std::stringbuf *pbuf=oss.rdbuf();
	size_t slen = strlen(pbuf->str().c_str());
	send(cmd_tunnel_sock,pbuf->str().c_str(),slen,0);

	slen = evbuffer_get_length(evb);
	uint8_t *data = evbuffer_pullup(evb,slen);
	send(cmd_tunnel_sock,(const char *)data,slen,0);

	evbuffer_drain(evb,slen);
}


void swift::CmdGwTunnelSendUDP(struct evbuffer *evb)
{
	// Received data from TCP connection, send over UDP to specified dest
	cmd_tunnel_state = CMDGW_TUNNEL_SCAN4CRLF;

	if (cmd_gw_debug)
		fprintf(stderr,"cmdgw: sendudp:");

	struct evbuffer *sendevbuf = evbuffer_new();

	// Add channel id 0xffffffff
	char prefix[4] = { 0xff, 0xff, 0xff, 0xff };
	int ret = evbuffer_add(sendevbuf,prefix,4);
	if (ret < 0)
	{
		evbuffer_drain(evb,cmd_tunnel_expect);
		evbuffer_free(sendevbuf);
		fprintf(stderr,"cmdgw: sendudp :can't copy prefix to sendbuf!");
		return;
	}
	ret = evbuffer_remove_buffer(evb, sendevbuf, cmd_tunnel_expect);
	if (ret < 0)
	{
		evbuffer_drain(evb,cmd_tunnel_expect);
		evbuffer_free(sendevbuf);
		fprintf(stderr,"cmdgw: sendudp :can't copy to sendbuf!");
		return;
	}
	if (Channel::sock_count != 1)
	{
		fprintf(stderr,"cmdgw: sendudp: no single UDP socket!");
		evbuffer_free(sendevbuf);
		return;
	}
	evutil_socket_t sock = Channel::sock_open[Channel::sock_count-1].sock;

	Channel::SendTo(sock,cmd_tunnel_dest_addr,sendevbuf);

	evbuffer_free(sendevbuf);
}
