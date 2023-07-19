#ifndef _PBUF_H_
#define _PBUF_H_

#include <stdint.h>

#include "err.h"
/**
 * @ingroup pbuf
 * Enumeration of pbuf layers
 */
typedef enum {
  /** Includes spare room for transport layer header, e.g. UDP header.
   * Use this if you intend to pass the pbuf to functions like udp_send().
   */
  PBUF_TRANSPORT,
  /** Includes spare room for IP header.
   * Use this if you intend to pass the pbuf to functions like raw_send().
   */
  PBUF_IP,
  /** Includes spare room for link layer header (ethernet header).
   * Use this if you intend to pass the pbuf to functions like ethernet_output().
   * @see PBUF_LINK_HLEN
   */
  PBUF_LINK,
  /** Includes spare room for additional encapsulation header before ethernet
   * headers (e.g. 802.11).
   * Use this if you intend to pass the pbuf to functions like netif->linkoutput().
   * @see PBUF_LINK_ENCAPSULATION_HLEN
   */
  PBUF_RAW_TX,
  /** Use this for input packets in a netif driver when calling netif->input()
   * in the most common case - ethernet-layer netif driver. */
  PBUF_RAW
} pbuf_layer;

/**
 * @ingroup pbuf
 * Enumeration of pbuf types
 */
typedef enum {
  /** pbuf data is stored in RAM, used for TX mostly, struct pbuf and its payload
      are allocated in one piece of contiguous memory (so the first payload byte
      can be calculated from struct pbuf).
      pbuf_alloc() allocates PBUF_RAM pbufs as unchained pbufs (although that might
      change in future versions).
      This should be used for all OUTGOING packets (TX).*/
  PBUF_RAM,
  /** pbuf data is stored in ROM, i.e. struct pbuf and its payload are located in
      totally different memory areas. Since it points to ROM, payload does not
      have to be copied when queued for transmission. */
  PBUF_ROM,
  /** pbuf comes from the pbuf pool. Much like PBUF_ROM but payload might change
      so it has to be duplicated when queued before transmitting, depending on
      who has a 'ref' to it. */
  PBUF_REF,
  /** pbuf payload refers to RAM. This one comes from a pool and should be used
      for RX. Payload can be chained (scatter-gather RX) but like PBUF_RAM, struct
      pbuf and its payload are allocated in one piece of contiguous memory (so
      the first payload byte can be calculated from struct pbuf).
      Don't use this for TX, if the pool becomes empty e.g. because of TCP queuing,
      you are unable to receive TCP acks! */
  PBUF_POOL
} pbuf_type;

/** indicates this packet's data should be immediately passed to the application */
#define PBUF_FLAG_PUSH      0x01U
/** indicates this is a custom pbuf: pbuf_free calls pbuf_custom->custom_free_function()
    when the last reference is released (plus custom PBUF_RAM cannot be trimmed) */
#define PBUF_FLAG_IS_CUSTOM 0x02U
/** indicates this pbuf is UDP multicast to be looped back */
#define PBUF_FLAG_MCASTLOOP 0x04U
/** indicates this pbuf was received as link-level broadcast */
#define PBUF_FLAG_LLBCAST   0x08U
/** indicates this pbuf was received as link-level multicast */
#define PBUF_FLAG_LLMCAST   0x10U
/** indicates this pbuf includes a TCP FIN flag */
#define PBUF_FLAG_TCP_FIN   0x20U

#define PBUF_OFFLOAD_IP_CHECKSUM    0x01U
#define PBUF_OFFLOAD_UDP_CHECKSUM   0x02U
#define PBUF_OFFLOAD_TCP_CHECKSUM   0x04U

/** Main packet buffer struct */
struct pbuf {
    /** next pbuf in singly linked pbuf chain */
    struct pbuf * next;

    /** pointer to the actual data in the buffer */
    void * payload;

    /**
     * total length of this buffer and all next buffers in chain
     * belonging to the same packet.
     *
     * For non-queue packet chains this is the invariant:
     * p->tot_len == p->len + (p->next? p->next->tot_len: 0)
     */
    uint16_t tot_len;

    /** length of this buffer */
    uint16_t len;

    /** pbuf_type as u8_t instead of enum to save space */
    uint8_t /*pbuf_type*/ type;
    
    /** misc flags */
    uint8_t flags;

    /** offload flags */
    uint8_t ol_flags;

    /**
     * the reference count always equals the number of pointers
     * that refer to this pbuf. This can be pointers from an application,
     * the stack itself, or pbuf->next pointers from a chain.
     */
    uint16_t ref;
};

extern struct pbuf * pbuf_alloc(pbuf_layer layer, uint16_t length, pbuf_type type);
extern err_t pbuf_copy(struct pbuf * p_to, const struct pbuf * p_from);
extern void pbuf_ref(struct pbuf * p);
extern uint8_t pbuf_free(struct pbuf * p);
extern uint16_t pbuf_clen(const struct pbuf * p);
extern uint8_t pbuf_header(struct pbuf * p, int16_t header_size);

#endif  /* _PBUF_H_ */