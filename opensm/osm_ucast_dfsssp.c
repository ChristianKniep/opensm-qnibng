/*
 * Copyright (c) 2004-2008 Voltaire, Inc. All rights reserved.
 * Copyright (c) 2002-2009 Mellanox Technologies LTD. All rights reserved.
 * Copyright (c) 1996-2003 Intel Corporation. All rights reserved.
 * Copyright (c) 2009-2011 ZIH, TU Dresden, Federal Republic of Germany. All rights reserved.
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

/*
 * Abstract:
 *    Implementation of OpenSM (deadlock-free) single-source-shortest-path routing
 *    (with dijkstra algorithm)
 */

#if HAVE_CONFIG_H
#  include <config.h>
#endif				/* HAVE_CONFIG_H */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <opensm/osm_file_ids.h>
#define FILE_ID OSM_FILE_UCAST_DFSSSP_C
#include <opensm/osm_ucast_mgr.h>
#include <opensm/osm_opensm.h>
#include <opensm/osm_node.h>

/* "infinity" for dijkstra */
#define INF      0x7FFFFFFF

enum {
	UNDISCOVERED = 0,
	DISCOVERED
};

enum {
	UNKNOWN = 0,
	GRAY,
	BLACK,
};

typedef struct link {
	uint64_t guid;		/* guid of the neighbor behind the link */
	uint32_t from;		/* base_index in the adjazenz list (start of the link) */
	uint8_t from_port;	/* port on the base_side (needed for weight update to identify the correct link for multigraphs) */
	uint32_t to;		/* index of the neighbor in the adjazenz list (end of the link) */
	uint8_t to_port;	/* port on the side of the neighbor (needed for the LFT) */
	uint64_t weight;	/* link weight */
	struct link *next;
} link_t;

typedef struct vertex {
	/* informations of the fabric */
	uint64_t guid;
	uint16_t lid;		/* for lft filling */
	uint32_t num_hca;	/* numbers of Hca/LIDs on the switch, for weight calculation */
	link_t *links;
	uint8_t hops;
	/* for dijkstra routing */
	link_t *used_link;	/* link between the vertex discovered before and this vertex */
	uint64_t distance;	/* distance from source to this vertex */
	uint8_t state;
	/* for the binary heap */
	uint32_t heap_id;
	/* for LFT writing and debug */
	osm_switch_t *sw;	/* selfpointer */
} vertex_t;

typedef struct binary_heap {
	uint32_t size;		/* size of the heap */
	vertex_t **nodes;	/* array with pointers to elements of the adj_list */
} binary_heap_t;

typedef struct vltable {
	uint64_t num_lids;	/* size of the lids array */
	uint16_t *lids;		/* sorted array of all lids in the subnet */
	uint8_t *vls;		/* matrix form assignment lid X lid -> virtual lane */
} vltable_t;

typedef struct cdg_link {
	struct cdg_node *node;
	uint32_t num_pairs;	/* number of src->dest pairs incremented in path adding step */
	uint32_t max_len;	/* length of the srcdest array */
	uint32_t removed;	/* number of pairs removed in path deletion step */
	uint32_t *srcdest_pairs;
	struct cdg_link *next;
} cdg_link_t;

/* struct for a node of a binary tree with additional parent pointer */
typedef struct cdg_node {
	uint64_t channelID;	/* unique key consist of src lid + port + dest lid + port */
	cdg_link_t *linklist;	/* edges to adjazent nodes */
	uint8_t status;		/* node status in cycle search to avoid recursive function */
	uint8_t visited;	/* needed to traverse the binary tree */
	struct cdg_node *pre;	/* to save the path in cycle detection algorithm */
	struct cdg_node *left, *right, *parent;
} cdg_node_t;

typedef struct dfsssp_context {
	osm_routing_engine_type_t routing_type;
	osm_ucast_mgr_t *p_mgr;
	vertex_t *adj_list;
	uint32_t adj_list_size;
	vltable_t *srcdest2vl_table;
} dfsssp_context_t;

/**************** set initial values for structs **********************
 **********************************************************************/
static inline void set_default_link(link_t * link)
{
	link->guid = 0;
	link->from = 0;
	link->from_port = 0;
	link->to = 0;
	link->to_port = 0;
	link->weight = 0;
	link->next = NULL;
}

static inline void set_default_vertex(vertex_t * vertex)
{
	vertex->guid = 0;
	vertex->lid = 0;
	vertex->num_hca = 0;
	vertex->links = NULL;
	vertex->hops = 0;
	vertex->used_link = NULL;
	vertex->distance = 0;
	vertex->state = UNDISCOVERED;
	vertex->heap_id = 0;
	vertex->sw = NULL;
}

static inline void set_default_cdg_node(cdg_node_t * node)
{
	node->channelID = 0;
	node->linklist = NULL;
	node->status = UNKNOWN;
	node->visited = 0;
	node->pre = NULL;
	node->left = NULL;
	node->right = NULL;
	node->parent = NULL;
}

/**********************************************************************
 **********************************************************************/

/************ helper functions for heap in dijkstra *******************
 **********************************************************************/
/* returns true if element 1 is smaller than element 2 */
static inline uint32_t heap_smaller(binary_heap_t * heap, uint32_t i,
				    uint32_t j)
{
	return (heap->nodes[i]->distance < heap->nodes[j]->distance) ? 1 : 0;
}

/* swap two elements */
static void heap_exchange(binary_heap_t * heap, uint32_t i, uint32_t j)
{
	uint32_t tmp_heap_id = 0;
	vertex_t *tmp_node = NULL;

	/* 1. swap the heap_id */
	tmp_heap_id = heap->nodes[i]->heap_id;
	heap->nodes[i]->heap_id = heap->nodes[j]->heap_id;
	heap->nodes[j]->heap_id = tmp_heap_id;
	/* 2. swap pointers */
	tmp_node = heap->nodes[i];
	heap->nodes[i] = heap->nodes[j];
	heap->nodes[j] = tmp_node;
}

/* changes position of element with parent until children are bigger */
static uint32_t heap_up(binary_heap_t * heap, uint32_t i)
{
	uint32_t curr = i, father = 0;

	if (curr > 0) {
		father = (curr - 1) >> 1;
		while (heap_smaller(heap, curr, father)) {
			heap_exchange(heap, curr, father);
			/* try to go up when we arent already root */
			curr = father;
			if (curr > 0)
				father = (curr - 1) >> 1;
		}
	}

	return curr;
}

/* changes position of element with children until parent is smaller */
static uint32_t heap_down(binary_heap_t * heap, uint32_t i)
{
	uint32_t curr = i;
	uint32_t son1 = 0, son2 = 0, smaller_son = 0;
	uint32_t exchanged = 0;

	do {
		son1 = ((curr + 1) << 1) - 1;
		son2 = (curr + 1) << 1;
		exchanged = 0;

		/* exchange with smaller son */
		if (son1 < heap->size && son2 < heap->size) {
			if (heap_smaller(heap, son1, son2))
				smaller_son = son1;
			else
				smaller_son = son2;
		} else if (son1 < heap->size) {
			/* only one son */
			smaller_son = son1;
		} else {
			/* finished */
			break;
		}

		/* only exchange when smaller */
		if (heap_smaller(heap, smaller_son, curr)) {
			heap_exchange(heap, curr, smaller_son);
			exchanged = 1;
			curr = smaller_son;
		}
	} while (exchanged);

	return curr;
}

/* reheapify element */
static inline void heap_heapify(binary_heap_t * heap, uint32_t i)
{
	heap_down(heap, heap_up(heap, i));
}

/* creates heap for graph */
static int heap_create(vertex_t * adj_list, uint32_t adj_list_size,
		       binary_heap_t ** binheap)
{
	binary_heap_t *heap = NULL;
	uint32_t i = 0;

	/* allocate the memory for the heap object */
	heap = (binary_heap_t *) malloc(sizeof(binary_heap_t));
	if (!heap)
		return 1;

	/* the heap size is equivalent to the size of the adj_list */
	heap->size = adj_list_size;

	/* allocate the pointer array, fill with the pointers to the elements of the adj_list and set the initial heap_id */
	heap->nodes = (vertex_t **) malloc(heap->size * sizeof(vertex_t *));
	if (!heap->nodes) {
		free(heap);
		return 1;
	}
	for (i = 0; i < heap->size; i++) {
		heap->nodes[i] = &adj_list[i];
		heap->nodes[i]->heap_id = i;
	}

	/* sort elements */
	for (i = heap->size; i > 0; i--)
		heap_down(heap, i - 1);

	*binheap = heap;
	return 0;
}

/* returns current minimum and removes it from heap */
static vertex_t *heap_getmin(binary_heap_t * heap)
{
	vertex_t *min = NULL;

	if (heap->size > 0)
		min = heap->nodes[0];

	if (min == NULL)
		return min;

	if (heap->size > 0) {
		if (heap->size > 1) {
			heap_exchange(heap, 0, heap->size - 1);
			heap->size--;
			heap_down(heap, 0);
		} else {
			heap->size--;
		}
	}

	return min;
}

/* cleanup heap */
static void heap_free(binary_heap_t * heap)
{
	if (heap) {
		if (heap->nodes) {
			free(heap->nodes);
			heap->nodes = NULL;
		}
		free(heap);
	}
}

/**********************************************************************
 **********************************************************************/

/************ helper functions to save src/dest X vl kombination ******
 **********************************************************************/
/* compare function of two lids for stdlib qsort */
static int cmp_lids(const void *l1, const void *l2)
{
	uint16_t lid1 = *((uint16_t *) l1), lid2 = *((uint16_t *) l2);

	if (lid1 < lid2)
		return -1;
	else if (lid1 > lid2)
		return 1;
	else
		return 0;
}

/* use stdlib to sort the lid array */
static inline void vltable_sort_lids(vltable_t * vltable)
{
	qsort(vltable->lids, vltable->num_lids, sizeof(uint16_t), cmp_lids);
}

/* use stdlib to get index of key in lid array;
   return -1 if lid isn't found in lids array
*/
static inline int64_t vltable_get_lidindex(uint16_t * key, vltable_t * vltable)
{
	uint16_t *found_lid = NULL;

	found_lid =
	    (uint16_t *) bsearch(key, vltable->lids, vltable->num_lids,
				 sizeof(uint16_t), cmp_lids);
	if (found_lid)
		return found_lid - vltable->lids;
	else
		return -1;
}

/* get virtual lane from src lid X dest lid kombination;
   return -1 for invalid lids
*/
static int32_t vltable_get_vl(vltable_t * vltable, uint16_t slid, uint16_t dlid)
{
	int64_t ind1 = vltable_get_lidindex(&slid, vltable);
	int64_t ind2 = vltable_get_lidindex(&dlid, vltable);

	if (ind1 > -1 && ind2 > -1)
		return (int32_t) (vltable->
				  vls[ind1 + ind2 * vltable->num_lids]);
	else
		return -1;
}

/* set a virtual lane in the matrix */
static inline void vltable_insert(vltable_t * vltable, uint16_t slid,
				  uint16_t dlid, uint8_t vl)
{
	int64_t ind1 = vltable_get_lidindex(&slid, vltable);
	int64_t ind2 = vltable_get_lidindex(&dlid, vltable);

	if (ind1 > -1 && ind2 > -1)
		vltable->vls[ind1 + ind2 * vltable->num_lids] = vl;
}

/* change a number of lanes from lane xy to lane yz */
static void vltable_change_vl(vltable_t * vltable, uint8_t from, uint8_t to,
			      uint64_t count)
{
	uint64_t set = 0, stop = 0;
	uint64_t ind1 = 0, ind2 = 0;

	for (ind1 = 0; ind1 < vltable->num_lids; ind1++) {
		for (ind2 = 0; ind2 < vltable->num_lids; ind2++) {
			if (set == count) {
				stop = 1;
				break;
			}
			if (ind1 != ind2) {
				if (vltable->
				    vls[ind1 + ind2 * vltable->num_lids] ==
				    from) {
					vltable->vls[ind1 +
						     ind2 * vltable->num_lids] =
					    to;
					set++;
				}
			}
		}
		if (stop)
			break;
	}
}

static void vltable_print(osm_ucast_mgr_t * p_mgr, vltable_t * vltable)
{
	uint64_t ind1 = 0, ind2 = 0;

	for (ind1 = 0; ind1 < vltable->num_lids; ind1++) {
		for (ind2 = 0; ind2 < vltable->num_lids; ind2++) {
			if (ind1 != ind2) {
				OSM_LOG(p_mgr->p_log, OSM_LOG_DEBUG,
					"   route from src_lid=%" PRIu16
					" to dest_lid=%" PRIu16 " on vl=%" PRIu8
					"\n", vltable->lids[ind1],
					vltable->lids[ind2],
					vltable->vls[ind1 +
						     ind2 * vltable->num_lids]);
			}
		}
	}
}

static void vltable_dealloc(vltable_t ** vltable)
{
	if (*vltable) {
		if ((*vltable)->lids)
			free((*vltable)->lids);
		if ((*vltable)->vls)
			free((*vltable)->vls);
		free(*vltable);
		*vltable = NULL;
	}
}

static int vltable_alloc(vltable_t ** vltable, uint64_t size)
{
	/* allocate VL table and indexing array */
	*vltable = (vltable_t *) malloc(sizeof(vltable_t));
	if (!(*vltable))
		goto ERROR;
	(*vltable)->num_lids = size;
	(*vltable)->lids = (uint16_t *) malloc(size * sizeof(uint16_t));
	if (!((*vltable)->lids))
		goto ERROR;
	(*vltable)->vls = (uint8_t *) malloc(size * size * sizeof(uint8_t));
	if (!((*vltable)->vls))
		goto ERROR;
	memset((*vltable)->vls, OSM_DEFAULT_SL, size * size);

	return 0;

ERROR:
	vltable_dealloc(vltable);

	return 1;
}

/**********************************************************************
 **********************************************************************/

/************ helper functions to save/manage the channel dep. graph **
 **********************************************************************/
/* update the srcdest array;
   realloc array (double the size) if size is not large enough
*/
static void set_next_srcdest_pair(cdg_link_t * link, uint32_t srcdest)
{
	uint32_t new_size = 0, start_size = 2;
	uint32_t *tmp = NULL, *tmp2 = NULL;

	if (link->num_pairs == 0) {
		link->srcdest_pairs =
		    (uint32_t *) malloc(start_size * sizeof(uint32_t));
		link->srcdest_pairs[link->num_pairs] = srcdest;
		link->max_len = start_size;
		link->removed = 0;
	} else if (link->num_pairs == link->max_len) {
		new_size = link->max_len << 1;
		tmp = (uint32_t *) malloc(new_size * sizeof(uint32_t));
		tmp =
		    memcpy(tmp, link->srcdest_pairs,
			   link->max_len * sizeof(uint32_t));
		tmp2 = link->srcdest_pairs;
		link->srcdest_pairs = tmp;
		link->srcdest_pairs[link->num_pairs] = srcdest;
		free(tmp2);
		link->max_len = new_size;
	} else {
		link->srcdest_pairs[link->num_pairs] = srcdest;
	}
	link->num_pairs++;
}

static inline uint32_t get_next_srcdest_pair(cdg_link_t * link, uint32_t index)
{
	return link->srcdest_pairs[index];
}

/* traverse binary tree to find a node */
static cdg_node_t *cdg_search(cdg_node_t * root, uint64_t channelID)
{
	while (root) {
		if (channelID < root->channelID)
			root = root->left;
		else if (channelID > root->channelID)
			root = root->right;
		else if (channelID == root->channelID)
			return root;
	}
	return NULL;
}

/* insert new node into the binary tree */
static void cdg_insert(cdg_node_t ** root, cdg_node_t * new_node)
{
	cdg_node_t *current = *root;

	if (!current) {
		current = new_node;
		*root = current;
		return;
	}

	while (current) {
		if (new_node->channelID < current->channelID) {
			if (current->left) {
				current = current->left;
			} else {
				current->left = new_node;
				new_node->parent = current;
				break;
			}
		} else if (new_node->channelID > current->channelID) {
			if (current->right) {
				current = current->right;
			} else {
				current->right = new_node;
				new_node->parent = current;
				break;
			}
		} else if (new_node->channelID == current->channelID) {
			/* not really possible, maybe programming error */
			break;
		}
	}
}

static void cdg_node_dealloc(cdg_node_t * node)
{
	cdg_link_t *link = node->linklist, *tmp = NULL;

	/* dealloc linklist */
	while (link) {
		tmp = link;
		link = link->next;

		if (tmp->num_pairs)
			free(tmp->srcdest_pairs);
		free(tmp);
	}
	/* dealloc node */
	free(node);
}

static void cdg_dealloc(cdg_node_t ** root)
{
	cdg_node_t *current = *root;

	while (current) {
		if (current->left) {
			current = current->left;
		} else if (current->right) {
			current = current->right;
		} else {
			if (current->parent == NULL) {
				cdg_node_dealloc(current);
				*root = NULL;
				break;
			}
			if (current->parent->left == current) {
				current = current->parent;
				cdg_node_dealloc(current->left);
				current->left = NULL;
			} else if (current->parent->right == current) {
				current = current->parent;
				cdg_node_dealloc(current->right);
				current->right = NULL;
			}
		}
	}
}

/* search for a edge in the cdg which should be removed to break a cycle */
static cdg_link_t *get_weakest_link_in_cycle(cdg_node_t * cycle)
{
	cdg_node_t *current = cycle, *node_with_weakest_link = NULL;
	cdg_link_t *link = NULL, *weakest_link = NULL;

	link = current->linklist;
	while (link) {
		if (link->node->status == GRAY) {
			weakest_link = link;
			node_with_weakest_link = current;
			current = link->node;
			break;
		}
		link = link->next;
	}

	while (1) {
		current->status = UNKNOWN;
		link = current->linklist;
		while (link) {
			if (link->node->status == GRAY) {
				if ((link->num_pairs - link->removed) <
				    (weakest_link->num_pairs -
				     weakest_link->removed)) {
					weakest_link = link;
					node_with_weakest_link = current;
				}
				current = link->node;
				break;
			}
			link = link->next;
		}
		/* if complete cycle is traversed */
		if (current == cycle) {
			current->status = UNKNOWN;
			break;
		}
	}

	if (node_with_weakest_link->linklist == weakest_link) {
		node_with_weakest_link->linklist = weakest_link->next;
	} else {
		link = node_with_weakest_link->linklist;
		while (link) {
			if (link->next == weakest_link) {
				link->next = weakest_link->next;
				break;
			}
			link = link->next;
		}
	}

	return weakest_link;
}

/* search for nodes in the cdg not yet reached in the cycle search process;
   (some nodes are unreachable, e.g. a node is a source or the cdg has not connected parts)
*/
static cdg_node_t *get_next_cdg_node(cdg_node_t * root)
{
	cdg_node_t *current = root, *res = NULL;

	while (current) {
		current->visited = 1;
		if (current->status == UNKNOWN) {
			res = current;
			break;
		}
		if (current->left && !current->left->visited) {
			current = current->left;
		} else if (current->right && !current->right->visited) {
			current = current->right;
		} else {
			if (current->left)
				current->left->visited = 0;
			if (current->right)
				current->right->visited = 0;
			if (current->parent == NULL)
				break;
			else
				current = current->parent;
		}
	}

	/* Clean up */
	while (current) {
		current->visited = 0;
		if (current->left)
			current->left->visited = 0;
		if (current->right)
			current->right->visited = 0;
		current = current->parent;
	}

	return res;
}

/* make a DFS on the cdg to check for a cycle */
static cdg_node_t *search_cycle_in_channel_dep_graph(cdg_node_t * cdg,
						     cdg_node_t * start_node)
{
	cdg_node_t *cycle = NULL;
	cdg_node_t *current = start_node, *next_node = NULL, *tmp = NULL;
	cdg_link_t *link = NULL;

	while (current) {
		current->status = GRAY;
		link = current->linklist;
		next_node = NULL;
		while (link) {
			if (link->node->status == UNKNOWN) {
				next_node = link->node;
				break;
			}
			if (link->node->status == GRAY) {
				cycle = link->node;
				goto Exit;
			}
			link = link->next;
		}
		if (next_node) {
			next_node->pre = current;
			current = next_node;
		} else {
			/* found a sink in the graph, go to last node */
			current->status = BLACK;

			/* srcdest_pairs of this node aren't relevant, free the allocated memory */
			link = current->linklist;
			while (link) {
				if (link->num_pairs)
					free(link->srcdest_pairs);
				link->srcdest_pairs = NULL;
				link->num_pairs = 0;
				link->removed = 0;
				link = link->next;
			}

			if (current->pre) {
				tmp = current;
				current = current->pre;
				tmp->pre = NULL;
			} else {
				/* search for other subgraphs in cdg */
				current = get_next_cdg_node(cdg);
				if (!current)
					break;	/* all relevant nodes traversed, no more cycles found */
			}
		}
	}

Exit:
	return cycle;
}

/* calculate the path from source to destination port;
   new channels are added directly to the cdg
*/
static int update_channel_dep_graph(cdg_node_t ** cdg_root,
				    osm_port_t * src_port, uint16_t slid,
				    osm_port_t * dest_port, uint16_t dlid)
{
	osm_node_t *local_node = NULL, *remote_node = NULL;
	uint16_t local_lid = 0, remote_lid = 0;
	uint32_t srcdest = 0;
	uint8_t local_port = 0, remote_port = 0;
	uint64_t channelID = 0;

	cdg_node_t *channel_head = NULL, *channel = NULL, *last_channel = NULL;
	cdg_link_t *linklist = NULL;

	/* set the identifier for the src/dest pair to save this on each edge of the cdg */
	srcdest = (((uint32_t) slid) << 16) + ((uint32_t) dlid);

	channel_head = (cdg_node_t *) malloc(sizeof(cdg_node_t));
	if (!channel_head)
		goto ERROR;
	set_default_cdg_node(channel_head);
	last_channel = channel_head;

	/* if src is a Hca, then the channel from Hca to switch would be a source in the graph
	   sources can't be part of a cycle -> skip this channel
	 */
	remote_node =
	    osm_node_get_remote_node(src_port->p_node,
				     src_port->p_physp->port_num, &remote_port);

	while (remote_node && remote_node->sw) {
		local_node = remote_node;
		local_port = local_node->sw->new_lft[dlid];
		local_lid = cl_ntoh16(osm_node_get_base_lid(local_node, 0));
		/* each port belonging to a switch has lmc==0 -> get_base_lid is fine
		   (local/remote port in this function are always part of a switch)
		 */

		remote_node =
		    osm_node_get_remote_node(local_node, local_port,
					     &remote_port);
		/* if remote_node is a Hca, then the last channel from switch to Hca would be a sink in the cdg -> skip */
		if (!remote_node->sw)
			break;
		remote_lid = cl_ntoh16(osm_node_get_base_lid(remote_node, 0));

		channelID =
		    (((uint64_t) local_lid) << 48) +
		    (((uint64_t) local_port) << 32) +
		    (((uint64_t) remote_lid) << 16) + ((uint64_t) remote_port);
		channel = cdg_search(*cdg_root, channelID);
		if (channel) {
			/* check whether last channel has connection to this channel, i.e. subpath already exists in cdg */
			linklist = last_channel->linklist;
			while (linklist && linklist->node != channel
			       && linklist->next)
				linklist = linklist->next;
			/* if there is no connection, add one */
			if (linklist) {
				if (linklist->node == channel) {
					set_next_srcdest_pair(linklist,
							      srcdest);
				} else {
					linklist->next =
					    (cdg_link_t *)
					    malloc(sizeof(cdg_link_t));
					if (!linklist->next)
						goto ERROR;
					linklist = linklist->next;
					linklist->node = channel;
					linklist->num_pairs = 0;
					linklist->srcdest_pairs = NULL;
					set_next_srcdest_pair(linklist,
							      srcdest);
					linklist->next = NULL;
				}
			} else {
				/* either this is the first channel of the path, or the last channel was a new channel, or last channel was a sink */
				last_channel->linklist =
				    (cdg_link_t *) malloc(sizeof(cdg_link_t));
				if (!last_channel->linklist)
					goto ERROR;
				last_channel->linklist->node = channel;
				last_channel->linklist->num_pairs = 0;
				last_channel->linklist->srcdest_pairs = NULL;
				set_next_srcdest_pair(last_channel->linklist,
						      srcdest);
				last_channel->linklist->next = NULL;
			}
		} else {
			/* create new channel */
			channel = (cdg_node_t *) malloc(sizeof(cdg_node_t));
			if (!channel)
				goto ERROR;
			set_default_cdg_node(channel);
			channel->channelID = channelID;
			cdg_insert(cdg_root, channel);

			/* go to end of link list of last channel */
			linklist = last_channel->linklist;
			while (linklist && linklist->next)
				linklist = linklist->next;
			if (linklist) {
				/* update last link of an existing channel */
				linklist->next =
				    (cdg_link_t *) malloc(sizeof(cdg_link_t));
				if (!linklist->next)
					goto ERROR;
				linklist = linklist->next;
				linklist->node = channel;
				linklist->num_pairs = 0;
				linklist->srcdest_pairs = NULL;
				set_next_srcdest_pair(linklist, srcdest);
				linklist->next = NULL;
			} else {
				/* either this is the first channel of the path, or the last channel was a new channel, or last channel was a sink */
				last_channel->linklist =
				    (cdg_link_t *) malloc(sizeof(cdg_link_t));
				if (!last_channel->linklist)
					goto ERROR;
				last_channel->linklist->node = channel;
				last_channel->linklist->num_pairs = 0;
				last_channel->linklist->srcdest_pairs = NULL;
				set_next_srcdest_pair(last_channel->linklist,
						      srcdest);
				last_channel->linklist->next = NULL;
			}
		}
		last_channel = channel;
	}

	if (channel_head->linklist) {
		if (channel_head->linklist->srcdest_pairs)
			free(channel_head->linklist->srcdest_pairs);
		free(channel_head->linklist);
	}
	free(channel_head);

	return 0;

ERROR:
	/* cleanup data and exit */
	if (channel_head) {
		if (channel_head->linklist)
			free(channel_head->linklist);
		free(channel_head);
	}

	return 1;
}

/* calculate the path from source to destination port;
   the links in the cdg representing this path are decremented to simulate the removal
*/
static int remove_path_from_cdg(cdg_node_t ** cdg_root, osm_port_t * src_port,
				uint16_t slid, osm_port_t * dest_port,
				uint16_t dlid)
{
	osm_node_t *local_node = NULL, *remote_node = NULL;
	uint16_t local_lid = 0, remote_lid = 0;
	uint8_t local_port = 0, remote_port = 0;
	uint64_t channelID = 0;

	cdg_node_t *channel_head = NULL, *channel = NULL, *last_channel = NULL;
	cdg_link_t *linklist = NULL;

	channel_head = (cdg_node_t *) malloc(sizeof(cdg_node_t));
	if (!channel_head)
		goto ERROR;
	set_default_cdg_node(channel_head);
	last_channel = channel_head;

	/* if src is a Hca, then the channel from Hca to switch would be a source in the graph
	   sources can't be part of a cycle -> skip this channel
	 */
	remote_node =
	    osm_node_get_remote_node(src_port->p_node,
				     src_port->p_physp->port_num, &remote_port);

	while (remote_node && remote_node->sw) {
		local_node = remote_node;
		local_port = local_node->sw->new_lft[dlid];
		local_lid = cl_ntoh16(osm_node_get_base_lid(local_node, 0));

		remote_node =
		    osm_node_get_remote_node(local_node, local_port,
					     &remote_port);
		/* if remote_node is a Hca, then the last channel from switch to Hca would be a sink in the cdg -> skip */
		if (!remote_node->sw)
			break;
		remote_lid = cl_ntoh16(osm_node_get_base_lid(remote_node, 0));

		channelID =
		    (((uint64_t) local_lid) << 48) +
		    (((uint64_t) local_port) << 32) +
		    (((uint64_t) remote_lid) << 16) + ((uint64_t) remote_port);
		channel = cdg_search(*cdg_root, channelID);
		if (channel) {
			/* check whether last channel has connection to this channel, i.e. subpath already exists in cdg */
			linklist = last_channel->linklist;
			while (linklist && linklist->node != channel
			       && linklist->next)
				linklist = linklist->next;
			/* remove the srcdest from the link */
			if (linklist) {
				if (linklist->node == channel) {
					linklist->removed++;
				} else {
					/* may happen if the link is missing (thru cycle detect algorithm) */
				}
			} else {
				/* may happen if the link is missing (thru cycle detect algorithm or last_channel==channel_head (dummy channel)) */
			}
		} else {
			/* must be an error, channels for the path are added before, so a missing channel would be a corrupt data structure */
			goto ERROR;
		}
		last_channel = channel;
	}

	if (channel_head->linklist)
		free(channel_head->linklist);
	free(channel_head);

	return 0;

ERROR:
	/* cleanup data and exit */
	if (channel_head) {
		if (channel_head->linklist)
			free(channel_head->linklist);
		free(channel_head);
	}

	return 1;
}

/**********************************************************************
 **********************************************************************/

static void dfsssp_print_graph(osm_ucast_mgr_t * p_mgr, vertex_t * adj_list,
			       uint32_t size)
{
	uint32_t i = 0, c = 0;
	link_t *link = NULL;

	/* index 0 is for the source in dijkstra -> ignore */
	for (i = 1; i < size; i++) {
		OSM_LOG(p_mgr->p_log, OSM_LOG_DEBUG, "adj_list[%" PRIu32 "]:\n",
			i);
		OSM_LOG(p_mgr->p_log, OSM_LOG_DEBUG,
			"   guid = 0x%" PRIx64 " lid = %" PRIu16 " (%s)\n",
			adj_list[i].guid, adj_list[i].lid,
			adj_list[i].sw->p_node->print_desc);
		OSM_LOG(p_mgr->p_log, OSM_LOG_DEBUG,
			"   num_hca = %" PRIu32 "\n", adj_list[i].num_hca);

		c = 1;
		for (link = adj_list[i].links; link != NULL;
		     link = link->next, c++) {
			OSM_LOG(p_mgr->p_log, OSM_LOG_DEBUG,
				"   link[%" PRIu32 "]:\n", c);
			OSM_LOG(p_mgr->p_log, OSM_LOG_DEBUG,
				"      to guid = 0x%" PRIx64 " (%s) port %"
				PRIu8 "\n", link->guid,
				adj_list[link->to].sw->p_node->print_desc,
				link->to_port);
			OSM_LOG(p_mgr->p_log, OSM_LOG_DEBUG,
				"      weight on this link = %" PRIu64 "\n",
				link->weight);
		}
	}
}

/* predefine, to use this in next function */
static void dfsssp_context_destroy(void *context);

/* traverse subnet to gather information about the connected switches */
static int dfsssp_build_graph(void *context)
{
	dfsssp_context_t *dfsssp_ctx = (dfsssp_context_t *) context;
	osm_ucast_mgr_t *p_mgr = (osm_ucast_mgr_t *) (dfsssp_ctx->p_mgr);

	cl_qmap_t *port_tbl = &p_mgr->p_subn->port_guid_tbl;	/* 1 managment port per switch + 1 or 2 ports for each Hca */
	osm_port_t *p_port = NULL;
	cl_qmap_t *sw_tbl = &p_mgr->p_subn->sw_guid_tbl;
	cl_map_item_t *item = NULL;
	osm_switch_t *sw = NULL;
	osm_node_t *remote_node = NULL;
	uint8_t port = 0, remote_port = 0;
	uint32_t i = 0, j = 0;
	uint64_t total_num_hca = 0;
	vertex_t *adj_list = NULL;
	osm_physp_t *p_physp = NULL;
	link_t *link = NULL, *head = NULL;
	uint32_t num_sw = 0, adj_list_size = 0;
	uint8_t lmc = 0;

	OSM_LOG_ENTER(p_mgr->p_log);
	OSM_LOG(p_mgr->p_log, OSM_LOG_VERBOSE,
		"Building graph for df-/sssp routing\n");

	/* if this pointer isn't NULL, this is a reroute step;
	   old context will be destroyed (adj_list and srcdest2vl_table)
	 */
	if (dfsssp_ctx->adj_list)
		dfsssp_context_destroy(context);

	num_sw = cl_qmap_count(sw_tbl);
	adj_list_size = num_sw + 1;
	/* allocate an adjazenz list (array), 0. element is reserved for the source (Hca) in the routing algo, others are switches */
	adj_list = (vertex_t *) malloc(adj_list_size * sizeof(vertex_t));
	if (!adj_list) {
		OSM_LOG(p_mgr->p_log, OSM_LOG_ERROR,
			"ERR AD02: cannot allocate memory for adj_list\n");
		return 1;
	}
	for (i = 0; i < adj_list_size; i++)
		set_default_vertex(&adj_list[i]);

	/* count the total number of Hca / LIDs (for lmc>0) in the fabric */
	for (item = cl_qmap_head(port_tbl); item != cl_qmap_end(port_tbl);
	     item = cl_qmap_next(item)) {
		p_port = (osm_port_t *) item;
		if (osm_node_get_type(p_port->p_node) == IB_NODE_TYPE_CA) {
			lmc = osm_port_get_lmc(p_port);
			total_num_hca += (1 << lmc);
		}
	}

	i = 1;			/* fill adj_list -> start with index 1 */
	for (item = cl_qmap_head(sw_tbl); item != cl_qmap_end(sw_tbl);
	     item = cl_qmap_next(item), i++) {
		sw = (osm_switch_t *) item;
		OSM_LOG(p_mgr->p_log, OSM_LOG_DEBUG,
			"Processing switch with GUID 0x%" PRIx64 "\n",
			cl_ntoh64(osm_node_get_node_guid(sw->p_node)));

		adj_list[i].guid =
		    cl_ntoh64(osm_node_get_node_guid(sw->p_node));
		adj_list[i].lid =
		    cl_ntoh16(osm_node_get_base_lid(sw->p_node, 0));
		adj_list[i].sw = sw;

		link = (link_t *) malloc(sizeof(link_t));
		if (!link) {
			OSM_LOG(p_mgr->p_log, OSM_LOG_ERROR,
				"ERR AD03: cannot allocate memory for a link\n");
			dfsssp_context_destroy(context);
			return 1;
		}
		head = link;
		head->next = NULL;

		/* iterate over all ports in the switch, start with port 1 (port 0 is a managment port) */
		for (port = 1; port < sw->num_ports; port++) {
			/* get the node behind the port */
			remote_node =
			    osm_node_get_remote_node(sw->p_node, port,
						     &remote_port);
			/* if there is no remote node on this port or it's the same switch -> try next port */
			if (!remote_node || remote_node->sw == sw)
				continue;
			/* make sure the link is healthy */
			p_physp = osm_node_get_physp_ptr(sw->p_node, port);
			if (!p_physp || !osm_link_is_healthy(p_physp))
				continue;
			/* if there is a Hca connected -> count and cycle */
			if (!remote_node->sw) {
				lmc = osm_port_get_lmc(p_port);
				adj_list[i].num_hca += (1 << lmc);
				continue;
			}
			OSM_LOG(p_mgr->p_log, OSM_LOG_DEBUG,
				"Node 0x%" PRIx64 ", remote node 0x%" PRIx64
				", port %" PRIu8 ", remote port %" PRIu8 "\n",
				cl_ntoh64(osm_node_get_node_guid(sw->p_node)),
				cl_ntoh64(osm_node_get_node_guid(remote_node)),
				port, remote_port);

			link->next = (link_t *) malloc(sizeof(link_t));
			if (!link->next) {
				OSM_LOG(p_mgr->p_log, OSM_LOG_ERROR,
					"ERR AD08: cannot allocate memory for a link\n");
				dfsssp_context_destroy(context);
				return 1;
			}
			link = link->next;
			set_default_link(link);
			link->guid =
			    cl_ntoh64(osm_node_get_node_guid(remote_node));
			link->from = i;
			link->from_port = port;
			link->to_port = remote_port;
			link->weight = total_num_hca * total_num_hca;	/* initilize with P^2 to force shortest paths */
		}

		adj_list[i].links = head->next;
		free(head);
	}
	/* connect the links with it's second adjacent node in the list */
	for (i = 1; i < adj_list_size; i++) {
		link = adj_list[i].links;
		while (link) {
			for (j = 1; j < adj_list_size; j++) {
				if (link->guid == adj_list[j].guid) {
					link->to = j;
					break;
				}
			}
			link = link->next;
		}
	}
	/* print the discovered graph */
	if (OSM_LOG_IS_ACTIVE_V2(p_mgr->p_log, OSM_LOG_DEBUG))
		dfsssp_print_graph(p_mgr, adj_list, adj_list_size);

	dfsssp_ctx->adj_list = adj_list;
	dfsssp_ctx->adj_list_size = adj_list_size;

	OSM_LOG_EXIT(p_mgr->p_log);
	return 0;
}

static void print_routes(osm_ucast_mgr_t * p_mgr, vertex_t * adj_list,
			 uint32_t adj_list_size, osm_port_t * port)
{
	uint32_t i = 0, j = 0;

	for (i = 1; i < adj_list_size; i++) {
		if (adj_list[i].state == DISCOVERED) {
			OSM_LOG(p_mgr->p_log, OSM_LOG_DEBUG,
				"Route from 0x%" PRIx64 " (%s) to 0x%" PRIx64
				" (%s):\n", adj_list[i].guid,
				adj_list[i].sw->p_node->print_desc,
				cl_ntoh64(osm_node_get_node_guid(port->p_node)),
				port->p_node->print_desc);
			j = i;
			while (adj_list[j].used_link) {
				if (j > 0) {
					OSM_LOG(p_mgr->p_log, OSM_LOG_DEBUG,
						"   0x%" PRIx64
						" (%s) routes thru port %" PRIu8
						"\n", adj_list[j].guid,
						adj_list[j].sw->p_node->
						print_desc,
						adj_list[j].used_link->to_port);
				} else {
					OSM_LOG(p_mgr->p_log, OSM_LOG_DEBUG,
						"   0x%" PRIx64
						" (%s) routes thru port %" PRIu8
						"\n", adj_list[j].guid,
						port->p_node->print_desc,
						adj_list[j].used_link->to_port);
				}
				j = adj_list[j].used_link->from;
			}
		}
	}
}

/* dijkstra step from one source to all switches in the df-/sssp graph */
static int dijkstra(osm_ucast_mgr_t * p_mgr, vertex_t * adj_list,
		    uint32_t adj_list_size, osm_port_t * port, uint16_t lid)
{
	uint32_t i = 0, j = 0, index = 0;
	osm_node_t *remote_node = NULL;
	uint8_t remote_port = 0;
	vertex_t *current = NULL;
	link_t *link = NULL;
	uint64_t guid = 0;
	binary_heap_t *heap = NULL;
	int err = 0;

	OSM_LOG_ENTER(p_mgr->p_log);

	/* reset all switches for new round with a new source for dijkstra */
	for (i = 1; i < adj_list_size; i++) {
		adj_list[i].hops = 0;
		adj_list[i].used_link = NULL;
		adj_list[i].distance = INF;
		adj_list[i].state = UNDISCOVERED;
	}

	/* if behind port is a Hca -> set adj_list[0] */
	if (osm_node_get_type(port->p_node) == IB_NODE_TYPE_CA) {
		/* save old link to prevent many mallocs after set_default_... */
		link = adj_list[0].links;
		/* initialize adj_list[0] (the source for the routing, a Hca) */
		set_default_vertex(&adj_list[0]);
		adj_list[0].guid =
		    cl_ntoh64(osm_node_get_node_guid(port->p_node));
		adj_list[0].lid = lid;
		index = 0;
		/* write saved link back to new adj_list[0] */
		adj_list[0].links = link;

		/* initialize link to neighbor for adj_list[0];
		   make sure the link is healthy
		 */
		if (port->p_physp && osm_link_is_healthy(port->p_physp)) {
			remote_node =
			    osm_node_get_remote_node(port->p_node,
						     port->p_physp->port_num,
						     &remote_port);
			/* if there is no remote node on this port or it's the same Hca -> ignore */
			if (remote_node
			    && (osm_node_get_type(remote_node) ==
				IB_NODE_TYPE_SWITCH)) {
				if (!(adj_list[0].links)) {
					adj_list[0].links =
					    (link_t *) malloc(sizeof(link_t));
					if (!(adj_list[0].links)) {
						OSM_LOG(p_mgr->p_log,
							OSM_LOG_ERROR,
							"ERR AD07: cannot allocate memory for a link\n");
						return 1;
					}
				}
				set_default_link(adj_list[0].links);
				adj_list[0].links->guid =
				    cl_ntoh64(osm_node_get_node_guid
					      (remote_node));
				adj_list[0].links->from_port =
				    port->p_physp->port_num;
				adj_list[0].links->to_port = remote_port;
				adj_list[0].links->weight = 1;
				for (j = 1; j < adj_list_size; j++) {
					if (adj_list[0].links->guid ==
					    adj_list[j].guid) {
						adj_list[0].links->to = j;
						break;
					}
				}
			}
		}
		/* if behind port is a switch -> search switch in adj_list */
	} else {
		/* reset adj_list[0], if links=NULL reset was done before, then skip */
		if (adj_list[0].links) {
			free(adj_list[0].links);
			set_default_vertex(&adj_list[0]);
		}
		/* search for the switch which is the source in this round */
		guid = cl_ntoh64(osm_node_get_node_guid(port->p_node));
		for (i = 1; i < adj_list_size; i++) {
			if (guid == adj_list[i].guid) {
				index = i;
				break;
			}
		}
	}

	/* source in dijkstra */
	adj_list[index].distance = 0;
	adj_list[index].state = DISCOVERED;
	adj_list[index].hops = 0;	/* the source has hop count = 0 */

	/* create a heap to find (efficient) the node with the smallest distance */
	if (osm_node_get_type(port->p_node) == IB_NODE_TYPE_CA)
		err = heap_create(adj_list, adj_list_size, &heap);
	else
		err = heap_create(&adj_list[1], adj_list_size - 1, &heap);
	if (err) {
		OSM_LOG(p_mgr->p_log, OSM_LOG_ERROR,
			"ERR AD09: cannot allocate memory for heap or heap->node in heap_create(...)\n");
		return err;
	}

	current = heap_getmin(heap);
	while (current) {
		current->state = DISCOVERED;
		if (current->used_link)	/* increment the number of hops to the source for each new node */
			current->hops =
			    adj_list[current->used_link->from].hops + 1;

		/* add/update nodes which aren't discovered but accessible */
		for (link = current->links; link != NULL; link = link->next) {
			if ((adj_list[link->to].state != DISCOVERED)
			    && (current->distance + link->weight <
				adj_list[link->to].distance)) {
				adj_list[link->to].used_link = link;
				adj_list[link->to].distance =
				    current->distance + link->weight;
				heap_heapify(heap, adj_list[link->to].heap_id);
			}
		}

		current = heap_getmin(heap);
	}

	/* destroy the heap */
	heap_free(heap);
	heap = NULL;

	OSM_LOG_EXIT(p_mgr->p_log);
	return 0;
}

/* update the linear forwarding tables of all switches with the informations
   from the last dijsktra step
*/
static int update_lft(osm_ucast_mgr_t * p_mgr, vertex_t * adj_list,
		      uint32_t adj_list_size, osm_port_t * p_port)
{
	uint32_t i = 0;
	int32_t index = -1;
	uint64_t guid;
	uint16_t lid = 0;
	uint8_t port = 0;
	uint8_t hops = 0;
	osm_switch_t *p_sw = NULL;
	boolean_t is_ignored_by_port_prof = FALSE;
	osm_physp_t *p = NULL;
	cl_status_t ret;

	OSM_LOG_ENTER(p_mgr->p_log);

	if (osm_node_get_type(p_port->p_node) == IB_NODE_TYPE_SWITCH) {
		/* we have to search for the right switch, with it's lid to update the LFT */
		guid = cl_ntoh64(osm_node_get_node_guid(p_port->p_node));
		for (i = 0; i < adj_list_size; i++) {
			if (adj_list[i].guid == guid) {
				index = i;
				break;
			}
		}
	} else {
		/* update the routing to a Hca -> index 0 contains the Hca */
		index = 0;
	}

	if (index >= 0) {
		lid = adj_list[index].lid;
	} else {
		OSM_LOG(p_mgr->p_log, OSM_LOG_ERROR,
			"ERR AD06: cannot find port in adj_list to run update_lft\n");
		return 1;
	}

	for (i = 1; i < adj_list_size; i++) {
		/* for each switch the port to the 'self'lid is the managment port (=0) */
		adj_list[i].sw->new_lft[adj_list[i].lid] = 0;
		/* the hop count to to the 'self'lid is 0 for each switch */
		osm_switch_set_hops(adj_list[i].sw, adj_list[i].lid, 0, 0);

		/* if no route goes thru this switch -> cycle */
		if (!(adj_list[i].used_link))
			continue;

		p_sw = adj_list[i].sw;
		hops = adj_list[i].hops;
		port = adj_list[i].used_link->to_port;
		/* the used_link is the link that was used in dijkstra to reach this node,
		   so the to_port is the local port on this node
		 */

		if (port == OSM_NO_PATH) {	/* if clause shouldn't be possible in this routing, but who cares */
			OSM_LOG(p_mgr->p_log, OSM_LOG_DEBUG,
				"No path to get to LID %" PRIu16
				" from switch 0x%" PRIx64 "\n", lid,
				cl_ntoh64(osm_node_get_node_guid
					  (p_sw->p_node)));

			/* do not try to overwrite the ppro of non existing port ... */
			is_ignored_by_port_prof = TRUE;
		} else {
			OSM_LOG(p_mgr->p_log, OSM_LOG_DEBUG,
				"Routing LID %" PRIu16 " to port %" PRIu8
				" for switch 0x%" PRIx64 "\n", lid, port,
				cl_ntoh64(osm_node_get_node_guid
					  (p_sw->p_node)));

			p = osm_node_get_physp_ptr(p_sw->p_node, port);

			/* we would like to optionally ignore this port in equalization
			   as in the case of the Mellanox Anafa Internal PCI TCA port
			 */
			is_ignored_by_port_prof = p->is_prof_ignored;

			/* We also would ignore this route if the target lid is of
			   a switch and the port_profile_switch_node is not TRUE
			 */
			if (!p_mgr->p_subn->opt.port_profile_switch_nodes)
				is_ignored_by_port_prof |=
				    (osm_node_get_type(p_port->p_node) ==
				     IB_NODE_TYPE_SWITCH);
		}

		/* to support lmc > 0 the functions alloc_ports_priv, free_ports_priv, find_and_add_remote_sys
		   from minhop aren't needed cause osm_switch_recommend_path is implicit calulated
		   for each LID pair thru dijkstra;
		   for each port the dijkstra algorithm calculates (max_lid_ho - min_lid_ho)-times maybe
		   disjoint routes to spread the bandwidth -> diffent routes for one port and lmc>0
		 */

		/* set port in LFT */
		p_sw->new_lft[lid] = port;
		if (!is_ignored_by_port_prof) {
			/* update the number of path routing thru this port */
			osm_switch_count_path(p_sw, port);
		}
		/* set te hop count from this switch to the lid */
		ret = osm_switch_set_hops(p_sw, lid, port, hops);
		if (ret != CL_SUCCESS)
			OSM_LOG(p_mgr->p_log, OSM_LOG_ERROR,
				"ERR AD05: cannot set hops for LID %" PRIu16
				" at switch 0x%" PRIx64 "\n", lid,
				cl_ntoh64(osm_node_get_node_guid
					  (p_sw->p_node)));
	}

	OSM_LOG_EXIT(p_mgr->p_log);
	return 0;
}

/* increment the edge weights of the df-/sssp graph which represent the number
   of paths on this link
*/
static void update_weights(osm_ucast_mgr_t * p_mgr, vertex_t * adj_list,
			   uint32_t adj_list_size, osm_port_t * port)
{
	uint32_t i = 0, j = 0;
	uint32_t additional_weight = 0;

	OSM_LOG_ENTER(p_mgr->p_log);

	for (i = 1; i < adj_list_size; i++) {
		/* if no route goes thru this switch -> cycle */
		if (!(adj_list[i].used_link))
			continue;
		/* if the source of dijkstra was a Hca -> add num_hca for the weight, else a weight of 1 */
		if (osm_node_get_type(port->p_node) == IB_NODE_TYPE_CA)
			additional_weight = adj_list[i].num_hca;
		else
			additional_weight = 1;

		j = i;
		while (adj_list[j].used_link) {
			/* update the link from pre to this node */
			adj_list[j].used_link->weight += additional_weight;

			j = adj_list[j].used_link->from;
		}
	}

	OSM_LOG_EXIT(p_mgr->p_log);
}

/* get the larges number of virtual lanes which is supported by all switches
   in the subnet
*/
static uint8_t get_avail_vl_in_subn(osm_ucast_mgr_t * p_mgr)
{
	uint32_t i = 0;
	uint8_t vls_avail = 0xFF, port_vls_avail = 0;
	cl_qmap_t *sw_tbl = &p_mgr->p_subn->sw_guid_tbl;
	cl_map_item_t *item = NULL;
	osm_switch_t *sw = NULL;

	/* traverse all switches to get the number of available virtual lanes in the subnet */
	for (item = cl_qmap_head(sw_tbl); item != cl_qmap_end(sw_tbl);
	     item = cl_qmap_next(item)) {
		sw = (osm_switch_t *) item;

		/* ignore managment port 0 */
		for (i = 1; i < osm_node_get_num_physp(sw->p_node); i++) {
			osm_physp_t *p_physp =
			    osm_node_get_physp_ptr(sw->p_node, i);

			if (p_physp && p_physp->p_remote_physp) {
				port_vls_avail =
				    ib_port_info_get_op_vls(&p_physp->
							    port_info);
				if (port_vls_avail
				    && port_vls_avail < vls_avail)
					vls_avail = port_vls_avail;
			}
		}
	}

	/* ib_port_info_get_op_vls gives values 1 ... 5 (s. IBAS 14.2.5.6) */
	vls_avail = 1 << (vls_avail - 1);

	/* set boundaries (s. IBAS 3.5.7) */
	if (vls_avail > 15)
		vls_avail = 15;
	if (vls_avail < 1)
		vls_avail = 1;

	return vls_avail;
}

/* search for cycles in the channel dependency graph to identify possible
   deadlocks in the network;
   assign new virtual lanes to some paths to break the deadlocks
*/
static int dfsssp_remove_deadlocks(dfsssp_context_t * dfsssp_ctx)
{
	osm_ucast_mgr_t *p_mgr = (osm_ucast_mgr_t *) dfsssp_ctx->p_mgr;

	cl_qmap_t *port_tbl = &p_mgr->p_subn->port_guid_tbl;	/* 1 managment port per switch + 1 or 2 ports for each Hca */
	cl_map_item_t *item1 = NULL, *item2 = NULL;
	osm_port_t *src_port = NULL, *dest_port = NULL;

	uint32_t i = 0, err = 0;
	uint8_t test_vl = 0, vl_avail = 0, vl_needed = 1;
	cdg_node_t **cdg = NULL, *start_here = NULL, *cycle = NULL;
	cdg_link_t *weakest_link = NULL;
	uint32_t srcdest = 0;

	vltable_t *srcdest2vl_table = NULL;
	uint8_t lmc = 0;
	uint16_t slid = 0, dlid = 0, min_lid_ho = 0, max_lid_ho =
	    0, min_lid_ho2 = 0, max_lid_ho2 = 0;;
	uint64_t *paths_per_vl = NULL;
	uint64_t from = 0, to = 0, count = 0;
	uint8_t *split_count = NULL;

	OSM_LOG_ENTER(p_mgr->p_log);
	OSM_LOG(p_mgr->p_log, OSM_LOG_VERBOSE,
		"Assign each src/dest pair a Virtual Lanes, to remove deadlocks in the routing\n");

	vl_avail = get_avail_vl_in_subn(p_mgr);
	OSM_LOG(p_mgr->p_log, OSM_LOG_INFO,
		"Virtual Lanes available: %" PRIu8 "\n", vl_avail);

	paths_per_vl = (uint64_t *) malloc(vl_avail * sizeof(uint64_t));
	if (!paths_per_vl) {
		OSM_LOG(p_mgr->p_log, OSM_LOG_ERROR,
			"ERR AD22: cannot allocate memory for paths_per_vl\n");
		return 1;
	}
	memset(paths_per_vl, 0, vl_avail * sizeof(uint64_t));

	cdg = (cdg_node_t **) malloc(vl_avail * sizeof(cdg_node_t *));
	if (!cdg) {
		OSM_LOG(p_mgr->p_log, OSM_LOG_ERROR,
			"ERR AD23: cannot allocate memory for cdg\n");
		free(paths_per_vl);
		return 1;
	}
	for (i = 0; i < vl_avail; i++)
		cdg[i] = NULL;

	count = 0;
	/* count all ports (also multiple LIDs) of type CA for size of VL table */
	for (item1 = cl_qmap_head(port_tbl); item1 != cl_qmap_end(port_tbl);
	     item1 = cl_qmap_next(item1)) {
		dest_port = (osm_port_t *) item1;
		if (osm_node_get_type(dest_port->p_node) == IB_NODE_TYPE_CA) {
			lmc = osm_port_get_lmc(dest_port);
			count += (1 << lmc);
		}
	}
	/* allocate VL table and indexing array */
	err = vltable_alloc(&srcdest2vl_table, count);
	if (err) {
		OSM_LOG(p_mgr->p_log, OSM_LOG_ERROR,
			"ERR AD26: cannot allocate memory for srcdest2vl_table\n");
		goto ERROR;
	}

	i = 0;
	/* fill lids into indexing array */
	for (item1 = cl_qmap_head(port_tbl); item1 != cl_qmap_end(port_tbl);
	     item1 = cl_qmap_next(item1)) {
		dest_port = (osm_port_t *) item1;
		if (osm_node_get_type(dest_port->p_node) == IB_NODE_TYPE_CA) {
			osm_port_get_lid_range_ho(dest_port, &min_lid_ho,
						  &max_lid_ho);
			for (dlid = min_lid_ho; dlid <= max_lid_ho; dlid++, i++)
				srcdest2vl_table->lids[i] = dlid;
		}
	}
	/* sort lids */
	vltable_sort_lids(srcdest2vl_table);

	test_vl = 0;
	/* fill cdg[0] with routes from each src/dest port combination for all Hca in the subnet */
	for (item1 = cl_qmap_head(port_tbl); item1 != cl_qmap_end(port_tbl);
	     item1 = cl_qmap_next(item1)) {
		dest_port = (osm_port_t *) item1;
		if (osm_node_get_type(dest_port->p_node) == IB_NODE_TYPE_CA) {

			for (item2 = cl_qmap_head(port_tbl);
			     item2 != cl_qmap_end(port_tbl);
			     item2 = cl_qmap_next(item2)) {
				src_port = (osm_port_t *) item2;
				if (osm_node_get_type(src_port->p_node) ==
				    IB_NODE_TYPE_CA && src_port != dest_port) {

					/* iterate over LIDs of src and dest port */
					osm_port_get_lid_range_ho(src_port,
								  &min_lid_ho,
								  &max_lid_ho);
					for (slid = min_lid_ho;
					     slid <= max_lid_ho; slid++) {
						osm_port_get_lid_range_ho
						    (dest_port, &min_lid_ho2,
						     &max_lid_ho2);
						for (dlid = min_lid_ho2;
						     dlid <= max_lid_ho2;
						     dlid++) {

							/* try to add the path to cdg[0] */
							err =
							    update_channel_dep_graph
							    (&(cdg[test_vl]),
							     src_port, slid,
							     dest_port, dlid);
							if (err) {
								OSM_LOG(p_mgr->
									p_log,
									OSM_LOG_ERROR,
									"ERR AD14: cannot allocate memory for cdg node or link in update_channel_dep_graph(...)\n");
								goto ERROR;
							}
							/* add the <s,d> kombination / coresponding virtual lane to the VL table */
							vltable_insert
							    (srcdest2vl_table,
							     slid, dlid,
							     test_vl);
							paths_per_vl[test_vl]++;

						}
					}

				}
			}

		}
	}
	dfsssp_ctx->srcdest2vl_table = srcdest2vl_table;

	/* test all cdg for cycles and break the cycles by moving paths on the weakest link to the next cdg */
	for (test_vl = 0; test_vl < vl_avail - 1; test_vl++) {
		start_here = cdg[test_vl];
		while (start_here) {
			cycle =
			    search_cycle_in_channel_dep_graph(cdg[test_vl],
							      start_here);

			if (cycle) {
				vl_needed = test_vl + 2;

				/* calc weakest link n cycle */
				weakest_link = get_weakest_link_in_cycle(cycle);
				if (!weakest_link) {
					OSM_LOG(p_mgr->p_log, OSM_LOG_ERROR,
						"ERR AD27: something went wrong in get_weakest_link_in_cycle(...)\n");
					goto ERROR;
				}

				paths_per_vl[test_vl] -=
				    weakest_link->num_pairs;
				paths_per_vl[test_vl + 1] +=
				    weakest_link->num_pairs;

				/* move all <s,d> paths on this link to the next cdg */
				for (i = 0; i < weakest_link->num_pairs; i++) {
					srcdest =
					    get_next_srcdest_pair(weakest_link,
								  i);
					slid = (uint16_t) (srcdest >> 16);
					dlid =
					    (uint16_t) ((srcdest << 16) >> 16);

					/* only move if not moved in a previous step */
					if (test_vl !=
					    (uint8_t)
					    vltable_get_vl(srcdest2vl_table,
							   slid, dlid))
						continue;

					src_port =
					    osm_get_port_by_lid(p_mgr->p_subn,
								cl_hton16
								(slid));
					dest_port =
					    osm_get_port_by_lid(p_mgr->p_subn,
								cl_hton16
								(dlid));

					/* remove path from current cdg / vl */
					err =
					    remove_path_from_cdg(&
								 (cdg[test_vl]),
								 src_port, slid,
								 dest_port,
								 dlid);
					if (err) {
						OSM_LOG(p_mgr->p_log,
							OSM_LOG_ERROR,
							"ERR AD44: something went wrong in remove_path_from_cdg(...)\n");
						goto ERROR;
					}

					/* add path to next cdg / vl */
					err =
					    update_channel_dep_graph(&
								     (cdg
								      [test_vl +
								       1]),
								     src_port,
								     slid,
								     dest_port,
								     dlid);
					if (err) {
						OSM_LOG(p_mgr->p_log,
							OSM_LOG_ERROR,
							"ERR AD14: cannot allocate memory for cdg node or link in update_channel_dep_graph(...)\n");
						goto ERROR;
					}
					vltable_insert(srcdest2vl_table, slid,
						       dlid, test_vl + 1);
				}

				if (weakest_link->num_pairs)
					free(weakest_link->srcdest_pairs);
				if (weakest_link)
					free(weakest_link);
			}

			start_here = cycle;
		}
	}

	/* test the last avail cdg for a cycle;
	   if there is one, than vl_needed > vl_avail
	 */
	start_here = cdg[vl_avail - 1];
	if (start_here) {
		cycle =
		    search_cycle_in_channel_dep_graph(cdg[vl_avail - 1],
						      start_here);
		if (cycle) {
			vl_needed = vl_avail + 1;
		}
	}

	OSM_LOG(p_mgr->p_log, OSM_LOG_INFO,
		"Virtual Lanes needed: %" PRIu8 "\n", vl_needed);
	if (OSM_LOG_IS_ACTIVE_V2(p_mgr->p_log, OSM_LOG_INFO)) {
		OSM_LOG(p_mgr->p_log, OSM_LOG_INFO,
			"Paths per VL (before balancing):\n");
		for (i = 0; i < vl_avail; i++)
			OSM_LOG(p_mgr->p_log, OSM_LOG_INFO,
				"   %" PRIu32 ". lane: %" PRIu64 "\n", i,
				paths_per_vl[i]);
	}

	OSM_LOG(p_mgr->p_log, OSM_LOG_VERBOSE,
		"Balancing the paths on the available Virtual Lanes\n");

	/* balancing virtual lanes, but avoid additional cycle check -> balancing suboptimal */
	if (vl_needed == 1) {
		from = 0;
		count = paths_per_vl[0] / vl_avail;
		for (to = 1; to < vl_avail; to++) {
			vltable_change_vl(srcdest2vl_table, from, to, count);
			paths_per_vl[from] -= count;
			paths_per_vl[to] += count;
		}
	} else if (vl_needed < vl_avail) {
		split_count = (uint8_t *) malloc(vl_needed * sizeof(uint8_t));
		if (!split_count) {
			OSM_LOG(p_mgr->p_log, OSM_LOG_ERROR,
				"ERR AD24: cannot allocate memory for split_count, skip balancing\n");
		} else {
			memset(split_count, 0, vl_needed * sizeof(uint8_t));
			for (i = vl_needed; i < vl_avail; i++)
				split_count[(i - vl_needed) % vl_needed]++;

			to = vl_needed;
			for (from = 0; from < vl_needed; from++) {
				count =
				    paths_per_vl[from] / (split_count[from] +
							  1);
				for (i = 0; i < split_count[from]; i++) {
					vltable_change_vl(srcdest2vl_table,
							  from, to, count);
					paths_per_vl[from] -= count;
					paths_per_vl[to] += count;
					to++;
				}
			}

			free(split_count);
		}
	} else if (vl_needed > vl_avail) {
		/* routing not possible, a further development would be the LASH-TOR approach (update: LASH-TOR isn't possible, there is a mistake in the theory) */
		OSM_LOG(p_mgr->p_log, OSM_LOG_ERROR,
			"ERR AD25: Not enough VL available (avail=%d, needed=%d); Stop dfsssp routing!\n",
			vl_avail, vl_needed);
		goto ERROR;
	}
	/* else { no balancing } */
	if (OSM_LOG_IS_ACTIVE_V2(p_mgr->p_log, OSM_LOG_INFO)) {
		OSM_LOG(p_mgr->p_log, OSM_LOG_DEBUG,
			"Virtual Lanes per src/dest combination after balancing:\n");
		vltable_print(p_mgr, srcdest2vl_table);
		OSM_LOG(p_mgr->p_log, OSM_LOG_INFO,
			"Paths per VL (after balancing):\n");
		for (i = 0; i < vl_avail; i++)
			OSM_LOG(p_mgr->p_log, OSM_LOG_INFO,
				"   %" PRIu32 ". lane: %" PRIu64 "\n", i,
				paths_per_vl[i]);
	}

	free(paths_per_vl);

	/* deallocate channel dependency graphs */
	for (i = 0; i < vl_avail; i++)
		cdg_dealloc(&cdg[i]);
	free(cdg);

	OSM_LOG_EXIT(p_mgr->p_log);
	return 0;

ERROR:
	free(paths_per_vl);

	for (i = 0; i < vl_avail; i++)
		cdg_dealloc(&cdg[i]);
	free(cdg);

	vltable_dealloc(&srcdest2vl_table);
	dfsssp_ctx->srcdest2vl_table = NULL;

	return err;
}

/* meta function which calls subfunctions for dijkstra, update lft and weights,
   (and remove deadklocks) to calculate the routing for the subnet
*/
static int dfsssp_do_dijkstra_routing(void *context)
{
	dfsssp_context_t *dfsssp_ctx = (dfsssp_context_t *) context;
	osm_ucast_mgr_t *p_mgr = (osm_ucast_mgr_t *) dfsssp_ctx->p_mgr;
	vertex_t *adj_list = (vertex_t *) dfsssp_ctx->adj_list;
	uint32_t adj_list_size = dfsssp_ctx->adj_list_size;

	cl_qmap_t *port_tbl = &p_mgr->p_subn->port_guid_tbl;	/* 1 managment port per switch + 1 or 2 ports for each Hca */
	cl_qmap_t *sw_tbl = &p_mgr->p_subn->sw_guid_tbl;
	cl_map_item_t *item = NULL;
	osm_switch_t *sw = NULL;
	osm_port_t *port = NULL;
	uint32_t i = 0, err = 0;
	uint16_t lid = 0, min_lid_ho = 0, max_lid_ho = 0;

	OSM_LOG_ENTER(p_mgr->p_log);
	OSM_LOG(p_mgr->p_log, OSM_LOG_VERBOSE,
		"Calculating shortest path from all Hca/switches to all\n");

	/* reset the new_lft for each switch */
	for (item = cl_qmap_head(sw_tbl); item != cl_qmap_end(sw_tbl);
	     item = cl_qmap_next(item)) {
		sw = (osm_switch_t *) item;
		/* initialize LIDs in buffer to invalid port number */
		memset(sw->new_lft, OSM_NO_PATH, sw->max_lid_ho + 1);
	}

	/* do the routing for the each Hca in the subnet */
	for (item = cl_qmap_head(port_tbl); item != cl_qmap_end(port_tbl);
	     item = cl_qmap_next(item)) {
		port = (osm_port_t *) item;

		/* if behind port is a Hca -> calculate shortest path with dijkstra from node to all switches/Hca */
		if (osm_node_get_type(port->p_node) == IB_NODE_TYPE_CA) {
			OSM_LOG(p_mgr->p_log, OSM_LOG_DEBUG,
				"Processing Hca with GUID 0x%" PRIx64 "\n",
				cl_ntoh64(osm_node_get_node_guid
					  (port->p_node)));

			/* distribute the LID range across the ports that can reach those LIDs
			   to have disjoint paths for one destination port with lmc>0
			 */
			osm_port_get_lid_range_ho(port, &min_lid_ho,
						  &max_lid_ho);
			for (lid = min_lid_ho; lid <= max_lid_ho; lid++) {
				/* do dijkstra from this Hca/LID to each switch */
				err =
				    dijkstra(p_mgr, adj_list, adj_list_size,
					     port, lid);
				if (err)
					return err;
				if (OSM_LOG_IS_ACTIVE_V2(p_mgr->p_log,
				    OSM_LOG_DEBUG))
					print_routes(p_mgr, adj_list,
						     adj_list_size, port);

				/* make an update for the linear forwarding tables of the switches */
				err =
				    update_lft(p_mgr, adj_list, adj_list_size,
					       port);
				if (err)
					return err;

				/* add weights for calculated routes to adjust the weights for the next cycle */
				update_weights(p_mgr, adj_list, adj_list_size,
					       port);

				if (OSM_LOG_IS_ACTIVE_V2(p_mgr->p_log,
				    OSM_LOG_DEBUG))
					dfsssp_print_graph(p_mgr, adj_list,
							   adj_list_size);
			}
		}
	}
	/* do the routing for the each switch in the subnet to add the routes from switch to switch */
	for (item = cl_qmap_head(port_tbl); item != cl_qmap_end(port_tbl);
	     item = cl_qmap_next(item)) {
		port = (osm_port_t *) item;

		if (osm_node_get_type(port->p_node) == IB_NODE_TYPE_SWITCH) {
			OSM_LOG(p_mgr->p_log, OSM_LOG_DEBUG,
				"Processing switch with GUID 0x%" PRIx64 "\n",
				cl_ntoh64(osm_node_get_node_guid
					  (port->p_node)));

			lid = cl_ntoh16(osm_node_get_base_lid(port->p_node, 0));
			/* do dijkstra from this switch to each switch */
			err =
			    dijkstra(p_mgr, adj_list, adj_list_size, port, lid);
			if (err)
				return err;
			if (OSM_LOG_IS_ACTIVE_V2(p_mgr->p_log, OSM_LOG_DEBUG))
				print_routes(p_mgr, adj_list, adj_list_size,
					     port);

			/* make an update for the linear forwarding tables of the switches */
			err = update_lft(p_mgr, adj_list, adj_list_size, port);
			if (err)
				return err;

			/* add weights for calculated routes to adjust the weights for the next cycle */
			update_weights(p_mgr, adj_list, adj_list_size, port);

			if (OSM_LOG_IS_ACTIVE_V2(p_mgr->p_log, OSM_LOG_DEBUG))
				dfsssp_print_graph(p_mgr, adj_list,
						   adj_list_size);
		}
	}

	/* try deadlock removal only for the dfsssp routing (not for the sssp case, which is a subset of the dfsssp algorithm) */
	if (dfsssp_ctx->routing_type == OSM_ROUTING_ENGINE_TYPE_DFSSSP) {
		/* remove potential deadlocks by assigning different virtual lanes to src/dest paths and balance the lanes */
		err = dfsssp_remove_deadlocks(dfsssp_ctx);
		if (err)
			return err;
	} else if (dfsssp_ctx->routing_type == OSM_ROUTING_ENGINE_TYPE_SSSP) {
		OSM_LOG(p_mgr->p_log, OSM_LOG_INFO,
			"SSSP routing specified -> skipping deadlock removal thru dfsssp_remove_deadlocks(...)\n");
	} else {
		OSM_LOG(p_mgr->p_log, OSM_LOG_ERROR,
			"ERR AD28: wrong routing engine specified in dfsssp_ctx\n");
		return 1;
	}

	/* print the new_lft for each switch after routing is done */
	if (OSM_LOG_IS_ACTIVE_V2(p_mgr->p_log, OSM_LOG_DEBUG)) {
		for (item = cl_qmap_head(sw_tbl); item != cl_qmap_end(sw_tbl);
		     item = cl_qmap_next(item)) {
			sw = (osm_switch_t *) item;
			OSM_LOG(p_mgr->p_log, OSM_LOG_DEBUG,
				"Summary of the (new) LFT for switch 0x%" PRIx64
				" (%s):\n",
				cl_ntoh64(osm_node_get_node_guid(sw->p_node)),
				sw->p_node->print_desc);
			for (i = 0; i < sw->max_lid_ho + 1; i++)
				if (sw->new_lft[i] != OSM_NO_PATH) {
					OSM_LOG(p_mgr->p_log, OSM_LOG_DEBUG,
						"   for LID=%" PRIu32
						" use port=%" PRIu8 "\n", i,
						sw->new_lft[i]);
				}
		}
	}

	OSM_LOG_EXIT(p_mgr->p_log);
	return 0;
}

/* called from extern in QP creation process to gain the the service level and
   the virtual lane respectively for a <s,d> pair
*/
static uint8_t get_dfsssp_sl(void *context, uint8_t hint_for_default_sl,
			     const ib_net16_t slid, const ib_net16_t dlid)
{
	dfsssp_context_t *dfsssp_ctx = (dfsssp_context_t *) context;
	osm_ucast_mgr_t *p_mgr = (osm_ucast_mgr_t *) dfsssp_ctx->p_mgr;
	osm_port_t *src_port, *dest_port;
	vltable_t *srcdest2vl_table = NULL;
	int32_t res = 0;

	if (dfsssp_ctx
	    && dfsssp_ctx->routing_type == OSM_ROUTING_ENGINE_TYPE_DFSSSP)
		srcdest2vl_table = (vltable_t *) (dfsssp_ctx->srcdest2vl_table);
	else
		return hint_for_default_sl;

	src_port = osm_get_port_by_lid(p_mgr->p_subn, slid);
	if (!src_port)
		return hint_for_default_sl;

	dest_port = osm_get_port_by_lid(p_mgr->p_subn, dlid);
	if (!dest_port)
		return hint_for_default_sl;

	if (!srcdest2vl_table)
		return hint_for_default_sl;

	res = vltable_get_vl(srcdest2vl_table, slid, dlid);

	if (res > -1)
		return (uint8_t) res;
	else
		return hint_for_default_sl;
}

static dfsssp_context_t *dfsssp_context_create(osm_opensm_t * p_osm,
					       osm_routing_engine_type_t
					       routing_type)
{
	dfsssp_context_t *dfsssp_ctx = NULL;

	/* allocate memory */
	dfsssp_ctx = (dfsssp_context_t *) malloc(sizeof(dfsssp_context_t));
	if (dfsssp_ctx) {
		/* set initial values */
		dfsssp_ctx->routing_type = routing_type;
		dfsssp_ctx->p_mgr = (osm_ucast_mgr_t *) & (p_osm->sm.ucast_mgr);
		dfsssp_ctx->adj_list = NULL;
		dfsssp_ctx->srcdest2vl_table = NULL;
	} else {
		OSM_LOG(p_osm->sm.ucast_mgr.p_log, OSM_LOG_ERROR,
			"ERR AD04: cannot allocate memory for dfsssp_ctx in dfsssp_context_create\n");
		return NULL;
	}

	return dfsssp_ctx;
}

static void dfsssp_context_destroy(void *context)
{
	dfsssp_context_t *dfsssp_ctx = (dfsssp_context_t *) context;
	vertex_t *adj_list = (vertex_t *) (dfsssp_ctx->adj_list);
	uint32_t i = 0;
	link_t *link = NULL, *tmp = NULL;

	/* free adj_list */
	for (i = 0; i < dfsssp_ctx->adj_list_size; i++) {
		link = adj_list[i].links;
		while (link) {
			tmp = link;
			link = link->next;
			free(tmp);
		}
	}
	free(adj_list);
	dfsssp_ctx->adj_list = NULL;

	/* free srcdest2vl table (can be done because, dfsssp_context_destroy is called after osm_get_dfsssp_sl) */
	vltable_dealloc(&(dfsssp_ctx->srcdest2vl_table));
	dfsssp_ctx->srcdest2vl_table = NULL;

	free(context);
}

static void delete(void *context)
{
	if (!context)
		return;
	dfsssp_context_destroy(context);
}

int osm_ucast_dfsssp_setup(struct osm_routing_engine *r, osm_opensm_t * p_osm)
{
	/* create context container and add ucast managment object */
	dfsssp_context_t *dfsssp_context =
	    dfsssp_context_create(p_osm, OSM_ROUTING_ENGINE_TYPE_DFSSSP);
	if (!dfsssp_context) {
		return 1;	/* alloc failed -> skip this routing */
	}

	/* reset function pointers to dfsssp routines */
	r->context = (void *)dfsssp_context;
	r->build_lid_matrices = dfsssp_build_graph;
	r->ucast_build_fwd_tables = dfsssp_do_dijkstra_routing;
	r->path_sl = get_dfsssp_sl;
	r->destroy = delete;

	return 0;
}

int osm_ucast_sssp_setup(struct osm_routing_engine *r, osm_opensm_t * p_osm)
{
	/* create context container and add ucast managment object */
	dfsssp_context_t *dfsssp_context =
	    dfsssp_context_create(p_osm, OSM_ROUTING_ENGINE_TYPE_SSSP);
	if (!dfsssp_context) {
		return 1;	/* alloc failed -> skip this routing */
	}

	/* reset function pointers to sssp routines */
	r->context = (void *)dfsssp_context;
	r->build_lid_matrices = dfsssp_build_graph;
	r->ucast_build_fwd_tables = dfsssp_do_dijkstra_routing;
	r->destroy = delete;

	return 0;
}
