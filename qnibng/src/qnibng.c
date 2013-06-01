/*
 * Copyright (c) 2008 Voltaire, Inc. All rights reserved.
 * Copyright (c) 2007 The Regents of the University of California.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 */

#if HAVE_CONFIG_H
#  include <config.h>
#endif
/* HAVE_CONFIG_H */
#include <netdb.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <dlfcn.h>
#include <stdint.h>
#include <complib/cl_qmap.h>
#include <complib/cl_passivelock.h>
#include <opensm/osm_version.h>
#include <opensm/osm_opensm.h>
#include <opensm/osm_log.h>
/* include to create UDP socket */
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
/* regex */
#include <regex.h>


/** =========================================================================
 * This is a simple example plugin which logs some of the events the OSM
 * generates to this interface.
 */
#define SAMPLE_PLUGIN_OUTPUT_FILE "/tmp/osm_sample_event_plugin_output"
/* define address and port of graphite aggregator */
#define SERVER "127.0.0.1"
#define PORT 2003
#define BufferLength 512

/* Initialize connection stuff */
static int conn = 0;
static int sd, length = sizeof(int);

typedef struct _log_events {
	FILE *log_file;
	osm_log_t *osmlog;
} _log_events_t;

int connect_carbon() {
    int rc = sizeof(int);
    if (conn == 0){
        conn = 1;
        printf("Start open socket\n");
        struct sockaddr_in serveraddr;
        struct hostent *hostp;
        /* get a socket descriptor */
        if((sd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
            perror("Client-socket() error\n");
            exit(-1);
        } else {
            printf("Connection established\n");
        }
     
        memset(&serveraddr, 0x00, sizeof(struct sockaddr_in));
        serveraddr.sin_family = AF_INET;
        serveraddr.sin_port = htons(PORT);
         
        if((serveraddr.sin_addr.s_addr = inet_addr(SERVER)) == (unsigned long)INADDR_NONE) {
            /* When passing the host name of the server as a */
            /* parameter to this program, use the gethostbyname() */
            /* function to retrieve the address of the host server. */
            /***************************************************/
            /* get host address */
            hostp = gethostbyname(SERVER);
            if(hostp == (struct hostent *)NULL) {
                printf("HOST NOT FOUND --> ");
                /* h_errno is usually defined */
                /* in netdb.h */
                printf("h_errno = %d\n",h_errno);
                close(sd);
                exit(-1);
            }
            memcpy(&serveraddr.sin_addr, hostp->h_addr, sizeof(serveraddr.sin_addr));
        }
         
        /* After the socket descriptor is received, the */
        /* connect() function is used to establish a */
        /* connection to the server. */
        /***********************************************/
        /* connect() to server. */
        if((rc = connect(sd, (struct sockaddr *)&serveraddr, sizeof(serveraddr))) < 0) {
            perror("Client-connect() error");
            close(sd);
            return -1;
        }
        conn = 2;
        printf("socket open\n");
    }
    if (conn == 1) {
        printf("socket not finished yet (sleep 100) \n");
        sleep(100);
    }
    return 0;
}

int send_metric(char *metric) {
    char temp;
    int rc = sizeof(int);
    rc = write(sd, metric, strlen(metric));
    if(rc < 0) {
        perror("Client-write() error");
        rc = getsockopt(sd, SOL_SOCKET, SO_ERROR, &temp, &length);
        if(rc == 0) {
            /* Print out the asynchronously received error. */
            errno = temp;
            perror("SO_ERROR was");
        }
        conn = 0;
        close(sd);
    }
    return rc;
}
/**** Regex Function
 * Might be to heavy for this function, due to the hight frequency
 * but for starters
 */
char *regexp (char *string, char *patrn, int *begin, int *end) {    
        int i, w=0, len;                 
        char *word = NULL;
        regex_t rgT;
        regmatch_t match;
        regcomp(&rgT,patrn,REG_EXTENDED);
        if ((regexec(&rgT,string,1,&match,0)) == 0) {
                *begin = (int)match.rm_so;
                *end = (int)match.rm_eo;
                len = *end-*begin;
                word=malloc(len+1);
                for (i=*begin; i<*end; i++) {
                        word[w] = string[i];
                        w++; }
                word[w]=0;
        }
        regfree(&rgT);
        return word;
}

/** =========================================================================
 */
static void *construct(osm_opensm_t *osm)
{
	_log_events_t *log = malloc(sizeof(*log));
	if (!log)
		return (NULL);

	log->log_file = fopen(SAMPLE_PLUGIN_OUTPUT_FILE, "a+");

	if (!(log->log_file)) {
		osm_log(&osm->log, OSM_LOG_ERROR,
			"Sample Event Plugin: Failed to open output file \"%s\"\n",
			SAMPLE_PLUGIN_OUTPUT_FILE);
		free(log);
		return (NULL);
	}

	log->osmlog = &osm->log;
	return ((void *)log);
}

/** =========================================================================
 */
static void destroy(void *_log)
{
	_log_events_t *log = (_log_events_t *) _log;
	fclose(log->log_file);
	free(log);
}

/** =========================================================================
 */
static void handle_port_counter(_log_events_t * log, osm_epi_pe_event_t * pc)
{
    if (pc->time_diff_s==0) {
        return;
    }
    connect_carbon();
    /* Variable and structure definitions. */
    int b,e;
    char *hostname = regexp(pc->port_id.node_name,"[a-z]+[0-9]+",&b,&e);
    char buf[BufferLength];
    sprintf(buf, "ib.%s.%i.err.link_err_recover %" PRIu64 " %jd\n",
	    hostname, pc->port_id.port_num,
	    (pc->link_err_recover/pc->time_diff_s), time(NULL));
    sprintf(&buf[strlen(buf)], "ib.%s.%i.err.link_downed %" PRIu64 " %jd\n",
	    hostname, pc->port_id.port_num,
	    (pc->link_downed/pc->time_diff_s), time(NULL));
    sprintf(&buf[strlen(buf)], "ib.%s.%i.err.rcv_err %" PRIu64 " %jd\n",
	    hostname, pc->port_id.port_num,
	    (pc->rcv_err/pc->time_diff_s), time(NULL));
    sprintf(&buf[strlen(buf)], "ib.%s.%i.err.rcv_rem_phys_err %" PRIu64 " %jd\n",
	    hostname, pc->port_id.port_num,
	    (pc->rcv_rem_phys_err/pc->time_diff_s), time(NULL));
    sprintf(&buf[strlen(buf)], "ib.%s.%i.err.rcv_switch_relay_err %" PRIu64 " %jd\n",
	    hostname, pc->port_id.port_num,
	    (pc->rcv_switch_relay_err/pc->time_diff_s), time(NULL));
    sprintf(&buf[strlen(buf)], "ib.%s.%i.err.xmit_discards %" PRIu64 " %jd\n",
	    hostname, pc->port_id.port_num,
	    (pc->xmit_discards/pc->time_diff_s), time(NULL));
    sprintf(&buf[strlen(buf)], "ib.%s.%i.err.xmit_constraint_err %" PRIu64 " %jd\n",
	    hostname, pc->port_id.port_num,
	    (pc->xmit_constraint_err/pc->time_diff_s), time(NULL));
    sprintf(&buf[strlen(buf)], "ib.%s.%i.err.rcv_constraint_err %" PRIu64 " %jd\n",
	    hostname, pc->port_id.port_num,
	    (pc->rcv_constraint_err/pc->time_diff_s), time(NULL));
    sprintf(&buf[strlen(buf)], "ib.%s.%i.err.link_integrity %" PRIu64 " %jd\n",
	    hostname, pc->port_id.port_num,
	    (pc->link_integrity/pc->time_diff_s), time(NULL));
    sprintf(&buf[strlen(buf)], "ib.%s.%i.err.buffer_overrun %" PRIu64 " %jd\n",
	    hostname, pc->port_id.port_num,
	    (pc->buffer_overrun/pc->time_diff_s), time(NULL));
    sprintf(&buf[strlen(buf)], "ib.%s.%i.err.vl15_dropped %" PRIu64 " %jd\n\0",
	    hostname, pc->port_id.port_num,
	    (pc->vl15_dropped/pc->time_diff_s), time(NULL));
    send_metric(buf);
}

/** =========================================================================
 */
static void handle_port_counter_ext(_log_events_t * log, osm_epi_dc_event_t * epc)
{
    if (epc->time_diff_s==0) {
        return;
    }
    connect_carbon();
	int b,e;
    char *hostname = regexp(epc->port_id.node_name,"[a-z]+[0-9]+",&b,&e);
    char buf[BufferLength];
    sprintf(buf, "ib.%s.%i.perf.rcv_data %" PRIu64 " %jd\n",
	    hostname, epc->port_id.port_num,
	    (epc->rcv_data/epc->time_diff_s), time(NULL));
    sprintf(&buf[strlen(buf)], "ib.%s.%i.perf.xmit_data %" PRIu64 " %jd\n",
	    hostname, epc->port_id.port_num,
	    (epc->xmit_data/epc->time_diff_s), time(NULL));
    sprintf(&buf[strlen(buf)], "ib.%s.%i.perf.rcv_pkts %" PRIu64 " %jd\n",
	    hostname, epc->port_id.port_num,
	    (epc->rcv_pkts/epc->time_diff_s), time(NULL));
    sprintf(&buf[strlen(buf)], "ib.%s.%i.perf.xmit_pkts %" PRIu64 " %jd\n",
	    hostname, epc->port_id.port_num,
	    (epc->xmit_pkts/epc->time_diff_s), time(NULL));
    send_metric(buf);
}

/** =========================================================================
 */
static void handle_port_select(_log_events_t * log, osm_epi_ps_event_t * ps)
{
	if (ps->xmit_wait > 0) {
		fprintf(log->log_file,
			"Port select Xmit Wait counts for node 0x%" PRIx64
			" (%s) port %d\n", ps->port_id.node_guid,
			ps->port_id.node_name, ps->port_id.port_num);
	}
}

/** =========================================================================
 */
static void handle_trap_event(_log_events_t *log, ib_mad_notice_attr_t *p_ntc)
{
	if (ib_notice_is_generic(p_ntc)) {
		fprintf(log->log_file,
			"Generic trap type %d; event %d; from LID 0x%x\n",
			ib_notice_get_type(p_ntc),
			cl_ntoh16(p_ntc->g_or_v.generic.trap_num),
			cl_ntoh16(p_ntc->issuer_lid));
	} else {
		fprintf(log->log_file,
			"Vendor trap type %d; from LID 0x%x\n",
			ib_notice_get_type(p_ntc),
			cl_ntoh16(p_ntc->issuer_lid));
	}

}

/** =========================================================================
 */
static void report(void *_log, osm_epi_event_id_t event_id, void *event_data)
{
	_log_events_t *log = (_log_events_t *) _log;

	switch (event_id) {
	case OSM_EVENT_ID_PORT_ERRORS:
		handle_port_counter(log, (osm_epi_pe_event_t *) event_data);
		break;
	case OSM_EVENT_ID_PORT_DATA_COUNTERS:
		handle_port_counter_ext(log, (osm_epi_dc_event_t *) event_data);
		break;
	case OSM_EVENT_ID_PORT_SELECT:
		handle_port_select(log, (osm_epi_ps_event_t *) event_data);
		break;
	case OSM_EVENT_ID_TRAP:
		handle_trap_event(log, (ib_mad_notice_attr_t *) event_data);
		break;
	case OSM_EVENT_ID_SUBNET_UP:
		fprintf(log->log_file, "Subnet up reported\n");
		break;
	case OSM_EVENT_ID_HEAVY_SWEEP_START:
		fprintf(log->log_file, "Heavy sweep started\n");
		break;
	case OSM_EVENT_ID_HEAVY_SWEEP_DONE:
		fprintf(log->log_file, "Heavy sweep completed\n");
		break;
	case OSM_EVENT_ID_UCAST_ROUTING_DONE:
		fprintf(log->log_file, "Unicast routing completed\n");
		break;
	case OSM_EVENT_ID_STATE_CHANGE:
		fprintf(log->log_file, "SM state changed\n");
		break;
	case OSM_EVENT_ID_SA_DB_DUMPED:
		fprintf(log->log_file, "SA DB dump file updated\n");
		break;
	case OSM_EVENT_ID_MAX:
	default:
		osm_log(log->osmlog, OSM_LOG_ERROR,
			"Unknown event (%d) reported to plugin\n", event_id);
	}
	fflush(log->log_file);
}

/** =========================================================================
 * Define the object symbol for loading
 */

#if OSM_EVENT_PLUGIN_INTERFACE_VER != 2
#error OpenSM plugin interface version missmatch
#endif

osm_event_plugin_t osm_event_plugin = {
      osm_version:OSM_VERSION,
      create:construct,
      delete:destroy,
      report:report
};
