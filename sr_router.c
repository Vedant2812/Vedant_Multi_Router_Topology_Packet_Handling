/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n",len);

  int sizeOfHeader = sizeof(sr_ethernet_hdr_t);
  int breakOut = 1;
  int store = 0;
  uint8_t *Dest = malloc(sizeof(uint8_t) * ETHER_ADDR_LEN);
  uint8_t *Src = malloc(sizeof(uint8_t) * ETHER_ADDR_LEN);

  sr_ethernet_hdr_t *Header = (sr_ethernet_hdr_t *) packet;

  memcpy(Dest, Header->ether_dhost, sizeof(uint8_t) * ETHER_ADDR_LEN);
  memcpy(Src, Header->ether_shost, sizeof(uint8_t) * ETHER_ADDR_LEN);
  uint16_t Pack = ntohs(Header->ether_type);  

  if(Header->ether_type == htons(ethertype_arp)) {
    sizeOfHeader = sizeOfHeader + sizeof(sr_arp_hdr_t);

    if(len >= sizeOfHeader) {
      breakOut = 0;
    }
  }
  else if(Header->ether_type == htons(ethertype_ip)) {
    store = sizeOfHeader;
    sr_ip_hdr_t *IPHeader = (sr_ip_hdr_t *)(packet + sizeOfHeader);
    sizeOfHeader = sizeOfHeader + sizeof(sr_ip_hdr_t);
    
    if(len >= sizeOfHeader) {
      uint16_t Temp3, Temp4;
      Temp3 = IPHeader->ip_sum;
      IPHeader->ip_sum = 0;
      Temp4 = cksum(IPHeader, sizeof(sr_ip_hdr_t));
      IPHeader->ip_sum = Temp3;
      if(Temp3 == Temp4) {
        if(IPHeader->ip_p == ip_protocol_icmp) {
           int temp3 = sizeOfHeader;
           sr_icmp_hdr_t * ICHeader = (sr_icmp_hdr_t *) (packet + sizeOfHeader);
           sizeOfHeader = sizeOfHeader + sizeof(sr_icmp_hdr_t);
           if(len >= sizeOfHeader) {
      	     Temp3 = ICHeader->icmp_sum;
             ICHeader->icmp_sum = 0;
             Temp4 = cksum(ICHeader, len - temp3);
             ICHeader->icmp_sum = Temp3;
             if(Temp3 == Temp4) {
               breakOut = 0;
             }
           }
        }
        else {
          breakOut = 0;
        }
      }
    }
  }
      

  if(breakOut == 0) {
    sizeOfHeader = sizeof(sr_ethernet_hdr_t);
    struct sr_if *inter2 = sr_get_interface(sr, interface);
    struct sr_rt *routing1 = sr->routing_table;
    sr_ethernet_hdr_t *HEAD = (sr_ethernet_hdr_t *) packet;

    if(Pack == ethertype_arp) {
      /*HANDLE ARP*/
      sizeOfHeader = sizeOfHeader + sizeof(sr_arp_hdr_t);

      sr_arp_hdr_t *ARPHeadPoint = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
      
      uint32_t keep1 = ntohl(inter2->ip);
      uint32_t keep2 = ntohl(ARPHeadPoint->ar_tip);
      uint32_t keep3 = ntohs(ARPHeadPoint->ar_op);
      if(keep1 == keep2) {
        if(arp_op_request == keep3) {
          uint8_t *Pack = (uint8_t *) malloc(sizeof(sr_arp_hdr_t) + sizeof(sr_ethernet_hdr_t));
          memset(Pack, 0, sizeof(sr_arp_hdr_t) + sizeof(sr_ethernet_hdr_t));
          memcpy(((sr_ethernet_hdr_t *) Pack)->ether_dhost, HEAD->ether_shost, ETHER_ADDR_LEN);
          memcpy(((sr_ethernet_hdr_t *) Pack)->ether_shost, inter2->addr, ETHER_ADDR_LEN);
          ((sr_ethernet_hdr_t *) Pack)->ether_type = htons(ethertype_arp);
          sr_arp_hdr_t *ARPHeader = (sr_arp_hdr_t *)(sizeof(sr_ethernet_hdr_t) + Pack);
          ARPHeader->ar_pro = htons(ethertype_ip);
          ARPHeader->ar_hln = ETHER_ADDR_LEN;
          ARPHeader->ar_op = htons(arp_op_reply);
          ARPHeader->ar_hrd = htons(arp_hrd_ethernet);
          ARPHeader->ar_pln = sizeof(uint32_t);
          ARPHeader->ar_sip = inter2->ip;
          ARPHeader->ar_tip = ARPHeadPoint->ar_sip;
          memcpy(ARPHeader->ar_sha, inter2->addr, ETHER_ADDR_LEN);
          memcpy(ARPHeader->ar_tha, ((sr_ethernet_hdr_t *) Pack)->ether_dhost, ETHER_ADDR_LEN);
          sr_send_packet(sr, Pack, sizeof(sr_arp_hdr_t) + sizeof(sr_ethernet_hdr_t), inter2->name);
          free(Pack);
        }
        keep1 = ntohs(ARPHeadPoint->ar_op);
        
        if(arp_op_reply == keep1) {
          struct sr_arpreq* C1 = sr_arpcache_insert(&(sr->cache), ARPHeadPoint->ar_sha, ARPHeadPoint->ar_sip);
          if(C1) {
            struct sr_packet* Pack1 = C1->packets;
            while(Pack1) {
              memcpy(((sr_ethernet_hdr_t *) (Pack1->buf))->ether_shost, inter2->addr, ETHER_ADDR_LEN);
              memcpy(((sr_ethernet_hdr_t *) (Pack1->buf))->ether_dhost, ARPHeadPoint->ar_sha, ETHER_ADDR_LEN);
              sr_send_packet(sr, Pack1->buf, Pack1->len, inter2->name);
              Pack1 = Pack1->next;
            }
            sr_arpreq_destroy(&(sr->cache), C1);
          }
        }
      }
    }
    else if(Pack == ethertype_ip) {
      sizeOfHeader = sizeOfHeader + sizeof(sr_ip_hdr_t);
      sr_ip_hdr_t *IPHeader = (sr_ip_hdr_t *)(sizeof(sr_ethernet_hdr_t) + packet);
      uint16_t Track = 0;
      sr_ip_hdr_t *temp1 = (sr_ip_hdr_t *) malloc(sizeof(sr_ip_hdr_t));
      memcpy(temp1, IPHeader, sizeof(sr_icmp_hdr_t));
      Track = temp1->ip_sum;
      temp1->ip_sum = 0;
      uint16_t Check = cksum(temp1, sizeof(sr_ip_hdr_t));
      
      if(Track == Check) {
        free(temp1);
      	return;
      }
      else {
        free(temp1);
      }
      
      struct sr_if *walker = sr->if_list;

      while(walker) {
        if(walker->ip == IPHeader->ip_dst) {
          break;
        }
        walker = walker->next;
      }
      
      if(!walker) {
        IPHeader->ip_ttl = IPHeader->ip_ttl - 1;
        if(!(IPHeader->ip_ttl)) {
          uint8_t *Pack = (uint8_t *) malloc(sizeof(sr_ip_hdr_t) 
		+ sizeof(sr_ethernet_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
          memset(Pack, 0, sizeof(sr_ip_hdr_t) + sizeof(sr_ethernet_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
          memcpy(((sr_ethernet_hdr_t *) Pack)->ether_dhost, HEAD->ether_shost, ETHER_ADDR_LEN);
          memcpy(((sr_ethernet_hdr_t *) Pack)->ether_shost, HEAD->ether_dhost, ETHER_ADDR_LEN);
          ((sr_ethernet_hdr_t *) Pack)->ether_type = htons(ethertype_ip);
          sr_ip_hdr_t *IPHeader1 = (sr_ip_hdr_t *)(sizeof(sr_ethernet_hdr_t) + Pack);
          IPHeader1->ip_p = ip_protocol_icmp;
          IPHeader1->ip_hl = 5;
          IPHeader1->ip_v = 4;
          IPHeader1->ip_ttl = INIT_TTL;
          IPHeader1->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
          IPHeader1->ip_tos = 0;
          IPHeader1->ip_sum = 0;
          IPHeader1->ip_id = 0;
          IPHeader1->ip_src = inter2->ip;
          IPHeader1->ip_dst = IPHeader->ip_src;
          IPHeader1->ip_sum = cksum(IPHeader1, sizeof(sr_ip_hdr_t));
          sr_icmp_t3_hdr_t *ICHeader = (sr_icmp_t3_hdr_t *)(sizeof(sr_ip_hdr_t) + sizeof(sr_ethernet_hdr_t)
		+ Pack);
          ICHeader->icmp_sum = 0;
          ICHeader->icmp_code = 0;
          ICHeader->icmp_type = 11;
          memcpy(ICHeader->data, sizeof(sr_ethernet_hdr_t) + packet, ICMP_DATA_SIZE);
          ICHeader->icmp_sum = cksum(ICHeader, sizeof(sr_icmp_t3_hdr_t));
          sr_send_packet(sr, Pack, sizeof(sr_ip_hdr_t) + sizeof(sr_ethernet_hdr_t) 
		+ sizeof(sr_icmp_t3_hdr_t), inter2->name);
          free(Pack);
          return;
        }
        IPHeader->ip_sum = 0;
        IPHeader->ip_sum = cksum(IPHeader, sizeof(sr_ip_hdr_t));
        uint32_t Val = 0, Val1 = 0, Val2 = 0, Val3 = 0;
        while(routing1) {
          Val = (uint32_t) routing1->mask.s_addr;
          if((IPHeader->ip_dst & Val) == (routing1->dest.s_addr & Val)) {
            Val2 = routing1->dest.s_addr;
            Val3 = routing1->gw.s_addr;
            Val1 = Val;
          }
          routing1 = routing1->next;
        }
        if(!Val2) {
          uint8_t *Pack = (uint8_t *) malloc(sizeof(sr_ip_hdr_t)
                + sizeof(sr_ethernet_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
          memset(Pack, 0, sizeof(sr_ip_hdr_t) + sizeof(sr_ethernet_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
          memcpy(((sr_ethernet_hdr_t *) Pack)->ether_dhost, HEAD->ether_shost, ETHER_ADDR_LEN);
          memcpy(((sr_ethernet_hdr_t *) Pack)->ether_shost, HEAD->ether_dhost, ETHER_ADDR_LEN);
          ((sr_ethernet_hdr_t *) Pack)->ether_type = htons(ethertype_ip);
          sr_ip_hdr_t *IPHeader1 = (sr_ip_hdr_t *)(sizeof(sr_ethernet_hdr_t) + Pack);
          IPHeader1->ip_p = ip_protocol_icmp;
          IPHeader1->ip_hl = 5;
          IPHeader1->ip_v = 4;
          IPHeader1->ip_ttl = INIT_TTL;
          IPHeader1->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
          IPHeader1->ip_tos = 0;
          IPHeader1->ip_sum = 0;
          IPHeader1->ip_id = 0;
          IPHeader1->ip_src = inter2->ip;
          IPHeader1->ip_dst = IPHeader->ip_src;
          IPHeader1->ip_sum = cksum(IPHeader1, sizeof(sr_ip_hdr_t));
          sr_icmp_t3_hdr_t *ICHeader = (sr_icmp_t3_hdr_t *)(sizeof(sr_ip_hdr_t) + sizeof(sr_ethernet_hdr_t)
                + Pack);
          ICHeader->icmp_sum = 0;
          ICHeader->icmp_code = 0;
          ICHeader->icmp_type = 3;
          memcpy(ICHeader->data, sizeof(sr_ethernet_hdr_t) + packet, ICMP_DATA_SIZE);
          ICHeader->icmp_sum = cksum(ICHeader, sizeof(sr_icmp_t3_hdr_t));
          sr_send_packet(sr, Pack, sizeof(sr_ip_hdr_t) + sizeof(sr_ethernet_hdr_t)
                + sizeof(sr_icmp_t3_hdr_t), inter2->name);
          free(Pack);
          return;
        }
	else {
          uint32_t hold1 = htonl(Val2);
          struct sr_arpentry *Hold = sr_arpcache_lookup(&(sr->cache), hold1);
          
          if(Hold) {
            struct sr_if *Inter1 = sr->if_list;
            
            while(Inter1) {
              if(Inter1->ip == Val3) {
                break;
              }
              Inter1 = Inter1->next;
            }
            
            memcpy(HEAD->ether_shost, Inter1->addr, ETHER_ADDR_LEN);
            memcpy(HEAD->ether_dhost, Hold->mac, ETHER_ADDR_LEN);
            sr_send_packet(sr, packet, len, Inter1->name);
            free(Hold);
          }
          else {
            sr_arpcache_queuereq(&(sr->cache), IPHeader->ip_dst, packet, len, inter2->name);
            struct sr_if *inter4=sr->if_list;
            while(inter4) {
              uint8_t *Pack = (uint8_t *) malloc(sizeof(sr_arp_hdr_t) + sizeof(sr_ethernet_hdr_t));
              memset(Pack, 0, sizeof(sr_arp_hdr_t) + sizeof(sr_ethernet_hdr_t));
              unsigned long long Mask = 0xFFFFFFFFFFFFFFFF;
              memcpy(((sr_ethernet_hdr_t *) Pack)->ether_dhost, &Mask, ETHER_ADDR_LEN);
              memcpy(((sr_ethernet_hdr_t *) Pack)->ether_shost, inter4->addr, ETHER_ADDR_LEN);
              ((sr_ethernet_hdr_t *) Pack)->ether_type = htons(ethertype_arp);
              sr_arp_hdr_t *ARPHeader = (sr_arp_hdr_t *)(sizeof(sr_ethernet_hdr_t) + Pack);
              ARPHeader->ar_pro = htons(ethertype_ip);
              ARPHeader->ar_hln = ETHER_ADDR_LEN;
              ARPHeader->ar_op = htons(arp_op_request);
              ARPHeader->ar_hrd = htons(arp_hrd_ethernet);
              ARPHeader->ar_pln = sizeof(uint32_t);
              ARPHeader->ar_sip = inter4->ip;
              ARPHeader->ar_tip = IPHeader->ip_dst;
              bzero(ARPHeader->ar_tha, ETHER_ADDR_LEN);
              memcpy(ARPHeader->ar_sha, ((sr_ethernet_hdr_t *) Pack)->ether_shost, ETHER_ADDR_LEN);
              sr_send_packet(sr, Pack, sizeof(sr_arp_hdr_t) + sizeof(sr_ethernet_hdr_t), inter4->name);
              free(Pack);
              inter4 = inter4->next;
            }        
          }
        }
      }    
      else {
        uint8_t Protocol = ip_protocol(sizeof(sr_ethernet_hdr_t) + packet);
        if(ip_protocol_icmp == Protocol) {
          sizeOfHeader = sizeOfHeader + sizeof(sr_icmp_hdr_t);
          sr_icmp_hdr_t *ICHeader = (sr_icmp_hdr_t *) (sizeof(sr_ip_hdr_t) + sizeof(sr_ethernet_hdr_t) + packet);
          if(ICHeader->icmp_type == 8) {
            ICHeader->icmp_type = 0;
            ICHeader->icmp_code = 0;
            ICHeader->icmp_sum = 0;
            ICHeader->icmp_sum = cksum(ICHeader, len - sizeof(sr_ip_hdr_t) - sizeof(sr_ethernet_hdr_t));
            uint8_t *Pack2 = (uint8_t *) malloc(ETHER_ADDR_LEN);
            memcpy(Pack2, HEAD->ether_dhost, ETHER_ADDR_LEN);
            memcpy(HEAD->ether_dhost, HEAD->ether_shost, ETHER_ADDR_LEN);
            memcpy(HEAD->ether_shost, Pack2, ETHER_ADDR_LEN);
            sr_ip_hdr_t *IPHeader = (sr_ip_hdr_t *)(packet + store);
            uint32_t temp = IPHeader->ip_src;
            IPHeader->ip_src = IPHeader->ip_dst;
            IPHeader->ip_sum = 0;
            IPHeader->ip_dst = temp;
            IPHeader->ip_sum = cksum(IPHeader, sizeof(sr_ip_hdr_t));
            sr_send_packet(sr, packet, len, inter2->name);
            return;
          }
        }
        if(Protocol == 17 || Protocol == 6) {
          uint8_t *Pack = (uint8_t *) malloc(sizeof(sr_ip_hdr_t)
                  + sizeof(sr_ethernet_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
          memset(Pack, 0, sizeof(sr_ip_hdr_t) + sizeof(sr_ethernet_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
          memcpy(((sr_ethernet_hdr_t *) Pack)->ether_dhost, HEAD->ether_shost, ETHER_ADDR_LEN);
          memcpy(((sr_ethernet_hdr_t *) Pack)->ether_shost, HEAD->ether_dhost, ETHER_ADDR_LEN);
          ((sr_ethernet_hdr_t *) Pack)->ether_type = htons(ethertype_ip);
          sr_ip_hdr_t *IPHeader1 = (sr_ip_hdr_t *)(sizeof(sr_ethernet_hdr_t) + Pack);
          IPHeader1->ip_p = ip_protocol_icmp;
          IPHeader1->ip_hl = 5;
          IPHeader1->ip_v = 4;
          IPHeader1->ip_ttl = INIT_TTL;
          IPHeader1->ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
          IPHeader1->ip_tos = 0;
          IPHeader1->ip_sum = 0;
          IPHeader1->ip_id = 0;
          IPHeader1->ip_src = inter2->ip;
          sr_ip_hdr_t *IPHeader = (sr_ip_hdr_t *)(packet + store);
          IPHeader1->ip_dst = IPHeader->ip_src;
          IPHeader1->ip_sum = cksum(IPHeader1, sizeof(sr_ip_hdr_t));
          sr_icmp_t3_hdr_t *ICHeader = (sr_icmp_t3_hdr_t *)(sizeof(sr_ip_hdr_t) + sizeof(sr_ethernet_hdr_t)
                + Pack);
          ICHeader->icmp_sum = 0;
          ICHeader->icmp_code = 3;
          ICHeader->icmp_type = 3;
          memcpy(ICHeader->data, sizeof(sr_ethernet_hdr_t) + packet, ICMP_DATA_SIZE);
          ICHeader->icmp_sum = cksum(ICHeader, sizeof(sr_icmp_t3_hdr_t));
          sr_send_packet(sr, Pack, sizeof(sr_ip_hdr_t) + sizeof(sr_ethernet_hdr_t)
                + sizeof(sr_icmp_t3_hdr_t), inter2->name);
          free(Pack);
          return;
        }
      }
    }
  }
}/* end sr_ForwardPacket */

