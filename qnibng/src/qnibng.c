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
/* define address and port of graphite aggregator / logstash */
#define LOGSTASH_HOST "logstash.syslog.service.consul"
#define LOGSTASH_PORT 5514
#define STATSD_HOST "statsd.service.consul"
#define STATSD_PORT 8125
#define BufferLength 512

/* Initialize connection stuff */
// statsd
static struct sockaddr_in statsd_serv_addr;
static int statsd_slen=sizeof(statsd_serv_addr);
// logstash
static struct sockaddr_in logstash_serv_addr;
static int logstash_slen=sizeof(logstash_serv_addr);

typedef struct _log_events {
	FILE *log_file;
	int *statsd_socket;
	int *logstash_socket;
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
    
	// Statsd socket
    if ((log->statsd_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP))==-1)
        err("socket");
	bzero(&statsd_serv_addr, sizeof(statsd_serv_addr));
    statsd_serv_addr.sin_family = AF_INET;
    statsd_serv_addr.sin_port = htons(STATSD_PORT);
    if (inet_aton(STATSD_HOST, &statsd_serv_addr.sin_addr)==0)
    {
        fprintf(stderr, "inet_aton() failed\n");
        exit(1);
    }
	// Logstash socket 5544
    if ((log->logstash_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP))==-1)
        err("socket");
	bzero(&logstash_serv_addr, sizeof(logstash_serv_addr));
    logstash_serv_addr.sin_family = AF_INET;
    logstash_serv_addr.sin_port = htons(LOGSTASH_PORT);
    if (inet_aton(LOGSTASH_HOST, &logstash_serv_addr.sin_addr)==0)
    {
        fprintf(stderr, "inet_aton() failed\n");
        exit(1);
    }

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
    /* Variable and structure definitions. */
    int b,e;
    char *hostname = regexp(pc->port_id.node_name,"[a-z]+[0-9]+",&b,&e);
    char buf[BufferLength];
    sprintf(buf, "ib.%s.%i.err.link_err_recover:+%lu|g\n",
        hostname, pc->port_id.port_num, pc->link_err_recover);
    sprintf(&buf[strlen(buf)], "ib.%s.%i.err.link_downed:+%lu|g\n",
        hostname, pc->port_id.port_num, pc->link_downed);
    sprintf(&buf[strlen(buf)], "ib.%s.%i.err.rcv_err:+%lu|g\n",
        hostname, pc->port_id.port_num, pc->rcv_err);
    sprintf(&buf[strlen(buf)], "ib.%s.%i.err.rcv_rem_phys_err:+%lu|g\n",
        hostname, pc->port_id.port_num, pc->rcv_rem_phys_err);
    sprintf(&buf[strlen(buf)], "ib.%s.%i.err.rcv_switch_relay_err:+%lu|g\n",
        hostname, pc->port_id.port_num, pc->rcv_switch_relay_err);
    sprintf(&buf[strlen(buf)], "ib.%s.%i.err.xmit_discards:+%lu|g\n",
        hostname, pc->port_id.port_num, pc->xmit_discards);
    sprintf(&buf[strlen(buf)], "ib.%s.%i.err.xmit_constraint_err:+%lu|g\n",
        hostname, pc->port_id.port_num, pc->xmit_constraint_err);
    sprintf(&buf[strlen(buf)], "ib.%s.%i.err.rcv_constraint_err:+%lu|g\n",
        hostname, pc->port_id.port_num, pc->rcv_constraint_err);
    sprintf(&buf[strlen(buf)], "ib.%s.%i.err.link_integrity:+%lu|g\n",
        hostname, pc->port_id.port_num, pc->link_integrity);
    sprintf(&buf[strlen(buf)], "ib.%s.%i.err.buffer_overrun:+%lu|g\n",
        hostname, pc->port_id.port_num, pc->buffer_overrun);
    if (pc->vl15_dropped != NULL) {
        sprintf(&buf[strlen(buf)], "ib.%s.%i.err.vl15_dropped:+%lu|g\n",
            hostname, pc->port_id.port_num, pc->vl15_dropped);
    }
	if (sendto(log->statsd_socket, buf, strlen(buf), 0, (struct sockaddr*)&statsd_serv_addr, statsd_slen)==-1)
        err("sendto()");
    //fprintf(log->log_file,buf);
}

/** =========================================================================
 */
static void handle_port_counter_ext(_log_events_t * log, osm_epi_dc_event_t * epc)
{
    if (epc->time_diff_s==0) {
        return;
    }
    if (epc->time_diff_s >= 10) {
        return;
    }
	int b,e;
    char *hostname = regexp(epc->port_id.node_name,"[a-z]+[0-9]+",&b,&e);
    char buf[BufferLength];
    sprintf(buf, "ib.%s.%i.perf.rcv_data:+%lu|g\n",
	    hostname, epc->port_id.port_num, epc->rcv_data);
    sprintf(&buf[strlen(buf)], "ib.%s.%i.perf.xmit_data:+%lu|g\n",
	    hostname, epc->port_id.port_num, epc->xmit_data);
	sprintf(&buf[strlen(buf)], "ib.%s.%i.perf.rcv_pkts:+%lu|g\n",
	    hostname, epc->port_id.port_num, epc->rcv_pkts);
    sprintf(&buf[strlen(buf)], "ib.%s.%i.perf.xmit_pkts:+%lu|g\n\0",
	    hostname, epc->port_id.port_num, epc->xmit_pkts);
    if (sendto(log->statsd_socket, buf, strlen(buf), 0, (struct sockaddr*)&statsd_serv_addr, statsd_slen)==-1)
        err("sendto()");
    //fprintf(log->log_file,buf);
}

/** =========================================================================
 */
static void handle_port_select(_log_events_t * log, osm_epi_ps_event_t * ps)
{
	if (ps->xmit_wait > 0) {
	    char buf[BufferLength];
		
	    sprintf(buf,
			"Port select Xmit Wait counts for node 0x%" PRIx64
			" (%s) port %d\n", ps->port_id.node_guid,
			ps->port_id.node_name, ps->port_id.port_num);
		fprintf(log->log_file,buf);
	    if (sendto(log->logstash_socket, buf, strlen(buf), 0, (struct sockaddr*)&logstash_serv_addr, logstash_slen)==-1)
			err("sendto()");
	}
}

/** =========================================================================
 */
static void handle_trap_event(_log_events_t *log, ib_mad_notice_attr_t *p_ntc)
{
	char buf[BufferLength];
	if (ib_notice_is_generic(p_ntc)) {
		if (cl_ntoh16(p_ntc->g_or_v.generic.trap_num) == 64) {
			sprintf(buf,
				"PortUp; Event %d; SwitchLID 0x%x; nodeGUID %lu\n",
				cl_ntoh16(p_ntc->g_or_v.generic.trap_num),
				cl_ntoh16(p_ntc->issuer_lid),
				p_ntc->data_details.ntc_64_67.gid.unicast.interface_id);
			} else if (cl_ntoh16(p_ntc->g_or_v.generic.trap_num) == 65) {
			sprintf(buf,
				"PortDown; Event %d; SwitchLID 0x%x; nodeGUID %lu\n",
				cl_ntoh16(p_ntc->g_or_v.generic.trap_num),
				cl_ntoh16(p_ntc->issuer_lid),
				p_ntc->data_details.ntc_64_67.gid.unicast.interface_id);
			} else {
			sprintf(buf,
				"Generic trap type %d; event %d; from LID 0x%x\n",
				ib_notice_get_type(p_ntc),
				cl_ntoh16(p_ntc->g_or_v.generic.trap_num),
				cl_ntoh16(p_ntc->issuer_lid));			
			}
	} else {
		sprintf(buf,
			"Vendor trap type %d; from LID 0x%x\n",
			ib_notice_get_type(p_ntc),
			cl_ntoh16(p_ntc->issuer_lid));
	}
	fprintf(log->log_file,buf);
	if (sendto(log->logstash_socket, buf, strlen(buf), 0, (struct sockaddr*)&logstash_serv_addr, logstash_slen)==-1)
		err("sendto()");
	

}

/** =========================================================================
 */
static void report(void *_log, osm_epi_event_id_t event_id, void *event_data)
{
	_log_events_t *log = (_log_events_t *) _log;

	char buf[BufferLength];
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
		sprintf(buf, "Subnet up reported\n");
		fprintf(log->log_file, buf);
		if (sendto(log->logstash_socket, buf, strlen(buf), 0, (struct sockaddr*)&logstash_serv_addr, logstash_slen)==-1)
			err("sendto()");
		break;
	case OSM_EVENT_ID_HEAVY_SWEEP_START:
		sprintf(buf, "Heavy sweep started\n");
		fprintf(log->log_file, buf);
		if (sendto(log->logstash_socket, buf, strlen(buf), 0, (struct sockaddr*)&logstash_serv_addr, logstash_slen)==-1)
			err("sendto()");
		break;
	case OSM_EVENT_ID_HEAVY_SWEEP_DONE:
		sprintf(buf, "Heavy sweep completed\n");
		fprintf(log->log_file, buf);
		if (sendto(log->logstash_socket, buf, strlen(buf), 0, (struct sockaddr*)&logstash_serv_addr, logstash_slen)==-1)
			err("sendto()");
		break;
	case OSM_EVENT_ID_UCAST_ROUTING_DONE:
		sprintf(buf, "Unicast routing completed\n");
		fprintf(log->log_file, buf);
		if (sendto(log->logstash_socket, buf, strlen(buf), 0, (struct sockaddr*)&logstash_serv_addr, logstash_slen)==-1)
			err("sendto()");
		break;
	case OSM_EVENT_ID_STATE_CHANGE:
		sprintf(buf, "SM state changed\n");
		fprintf(log->log_file, buf);
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
