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
#endif				/* HAVE_CONFIG_H */

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
#define SRV_IP "127.0.0.1"
#define PORT 2003
#define BUFLEN 512

typedef struct _log_events {
	FILE *log_file;
	osm_log_t *osmlog;
} _log_events_t;

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
	/*
	if (pc->symbol_err_cnt > 0
	    || pc->link_err_recover > 0
	    || pc->link_downed > 0
	    || pc->rcv_err > 0
	    || pc->rcv_rem_phys_err > 0
	    || pc->rcv_switch_relay_err > 0
	    || pc->xmit_discards > 0
	    || pc->xmit_constraint_err > 0
	    || pc->rcv_constraint_err > 0
	    || pc->link_integrity > 0
	    || pc->buffer_overrun > 0 || pc->vl15_dropped > 0) {
		fprintf(log->log_file,
			"Port counter errors for node 0x%" PRIx64
			" (%s) port %d\n", pc->port_id.node_guid,
			pc->port_id.node_name, pc->port_id.port_num);
	}
	*/
	/* create global socket */
	struct sockaddr_in si_other;
	int s, i, slen=sizeof(si_other);
	char buf[BUFLEN];
	if ((s=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP))==-1)
		fprintf(log->log_file, "socket creation failed\n");
	memset((char *) &si_other, 0, sizeof(si_other));
	si_other.sin_family = AF_INET;
	si_other.sin_port = htons(PORT);
	if (inet_aton(SRV_IP, &si_other.sin_addr)==0) {
		fprintf(log->log_file, "perf_cnt: inet_aton() failed\n");
		/*exit(1);*/
	}
	int b,e;
	char *hostname = regexp(pc->port_id.node_name,"[a-z]+[0-9]+",&b,&e);
	sprintf(buf, "ib.%s.%d.err.link_err_recover %d %d\n",
		hostname, pc->port_id.port_num,
		pc->link_err_recover, time(NULL));
	sprintf(&buf[strlen(buf)], "ib.%s.%d.err.link_downed %d %d\n",
		hostname, pc->port_id.port_num,
		pc->link_downed, time(NULL));
	sprintf(&buf[strlen(buf)], "ib.%s.%d.err.rcv_err %d %d\n",
		hostname, pc->port_id.port_num,
		pc->rcv_err, time(NULL));
	sprintf(&buf[strlen(buf)], "ib.%s.%d.err.rcv_rem_phys_err %d %d\n",
		hostname, pc->port_id.port_num,
		pc->rcv_rem_phys_err, time(NULL));
	sprintf(&buf[strlen(buf)], "ib.%s.%d.err.rcv_switch_relay_err %d %d\n",
		hostname, pc->port_id.port_num,
		pc->rcv_switch_relay_err, time(NULL));
	sprintf(&buf[strlen(buf)], "ib.%s.%d.err.xmit_discards %d %d\n",
		hostname, pc->port_id.port_num,
		pc->xmit_discards, time(NULL));
	sprintf(&buf[strlen(buf)], "ib.%s.%d.err.xmit_constraint_err %d %d\n",
		hostname, pc->port_id.port_num,
		pc->xmit_constraint_err, time(NULL));
	sprintf(&buf[strlen(buf)], "ib.%s.%d.err.rcv_constraint_err %d %d\n",
		hostname, pc->port_id.port_num,
		pc->rcv_constraint_err, time(NULL));
	sprintf(&buf[strlen(buf)], "ib.%s.%d.err.link_integrity %d %d\n",
		hostname, pc->port_id.port_num,
		pc->link_integrity, time(NULL));
	sprintf(&buf[strlen(buf)], "ib.%s.%d.err.buffer_overrun %d %d\n",
		hostname, pc->port_id.port_num,
		pc->buffer_overrun, time(NULL));
	sprintf(&buf[strlen(buf)], "ib.%s.%d.err.vl15_dropped %d %d\n",
		hostname, pc->port_id.port_num,
		pc->vl15_dropped, time(NULL));
	fprintf(log->log_file, buf);
	if (sendto(s, buf, BUFLEN, 0, &si_other, slen)==-1)
		fprintf(log->log_file, "sending 2nd buffer to graphite failed\n");
	shutdown(s, 0);
}

/** =========================================================================
 */
static void handle_port_counter_ext(_log_events_t * log, osm_epi_dc_event_t * epc)
{
	/* create global socket */
	struct sockaddr_in si_other;
	int s, i, slen=sizeof(si_other);
	char buf[BUFLEN];
	if ((s=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP))==-1)
		fprintf(log->log_file, "socket creation failed\n");
	memset((char *) &si_other, 0, sizeof(si_other));
	si_other.sin_family = AF_INET;
	si_other.sin_port = htons(PORT);
	if (inet_aton(SRV_IP, &si_other.sin_addr)==0) {
		fprintf(log->log_file, "perf_cnt: inet_aton() failed\n");
		/*exit(1);*/
	}
	int b,e;
	char *hostname = regexp(epc->port_id.node_name,"[a-z]+[0-9]+",&b,&e);
	sprintf(buf, 
		"ib.%s.%d.perf.rcv_data %d %d\n\0",
		hostname,
		epc->port_id.port_num,
		epc->rcv_data,
		time(NULL));
	sprintf(&buf[strlen(buf)], 
		"ib.%s.%d.perf.xmit_data %d %d\n\0",
		hostname,
		epc->port_id.port_num,
		epc->xmit_data,
		time(NULL));
	fprintf(log->log_file, buf);
	/* sending buffer to graphite */
	if (sendto(s, buf, strlen(buf), 0, &si_other, slen)==-1)
		fprintf(log->log_file, "sending buffer to graphite failed\n");
	shutdown(s, 0);

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
