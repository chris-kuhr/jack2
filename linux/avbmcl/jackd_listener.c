/*
Copyright (c) 2013 Katja Rohloff <katja.rohloff@uni-jena.de>

Permission is hereby granted, free of charge, to any person obtaining a
copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be included
in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#define _GNU_SOURCE

#include <errno.h>
#include <signal.h>

#include "avb_sockets.h"

#include <jack/jack.h>
#include <jack/ringbuffer.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

//#include <net/if.h>
#include <linux/if_link.h> /* depend on kernel-headers installed */

#include "./libbpf/include/uapi/linux/if_xdp.h"
#include "./headers/bpf_util.h" /* bpf_num_possible_cpus */
#include "./common/common_params.h"
#include "./common/common_user_bpf_xdp.h"
#include "common_kern_user.h"

#include "listener_mrp_client.h"


#define VERSION_STR "1.1"

#define ETHERNET_HEADER_SIZE (18)
#define SEVENTEEN22_HEADER_PART1_SIZE (4)
#define STREAM_ID_SIZE (8)
#define SEVENTEEN22_HEADER_PART2_SIZE (10)
#define SIX1883_HEADER_SIZE (10)
#define HEADER_SIZE (ETHERNET_HEADER_SIZE		\
			+ SEVENTEEN22_HEADER_PART1_SIZE \
			+ STREAM_ID_SIZE		\
			+ SEVENTEEN22_HEADER_PART2_SIZE \
			+ SIX1883_HEADER_SIZE)
#define SAMPLES_PER_SECOND (48000)
#define SAMPLES_PER_FRAME (6)
#define CHANNELS (2)
#define SAMPLE_SIZE (4)
#define DEFAULT_RINGBUFFER_SIZE (32768)
#define MAX_SAMPLE_VALUE ((1U << ((sizeof(int32_t) * 8) -1)) -1)






#define AVB_XDP




struct mrp_listener_ctx *ctx_sig;//Context pointer for signal handler

struct ethernet_header{
	u_char dst[6];
	u_char src[6];
	u_char stuff[4];
	u_char type[2];
};

/* globals */

static const char *version_str = "jackd_listener v" VERSION_STR "\n"
    "Copyright (c) 2013, Katja Rohloff, Copyright (c) 2019, Christoph Kuhr\n";


u_char glob_ether_type[] = { 0x22, 0xf0 };
static jack_port_t** outputports;
static jack_default_audio_sample_t** out;
jack_ringbuffer_t* ringbuffer;
jack_client_t* client;
volatile int ready = 0;
unsigned char glob_station_addr[] = { 0, 0, 0, 0, 0, 0 };
unsigned char glob_stream_id[] = { 0, 0, 0, 0, 0, 0, 0, 0 };
/* IEEE 1722 reserved address */
unsigned char glob_dest_addr[] = { 0x91, 0xE0, 0xF0, 0x00, 0x0e, 0x80 };
struct pollfd *avtp_transport_socket_fds;


#ifdef AVB_XDP

static const char *default_filename = "/home/soundjack/OpenAvnu.git.kuhr.xdp/examples/jackd-listener/xdp_avb_kern.o";
static const char *default_progsec = "xdp_avtp";

struct record {
	__u64 timestamp;
	struct datarec total;
};

struct stats_rec {
	struct record stats[1];
};

int find_map_fd(struct bpf_object *bpf_obj, const char *mapname)
{
	struct bpf_map *map;
	int map_fd = -1;

	/* bpf_object to bpf_map */
	map = bpf_object__find_map_by_name(bpf_obj, mapname);
        if (!map) {
		fprintf(stderr, "ERR: cannot find map by name: %s\n", mapname);
		goto out;
	}

	map_fd = bpf_map__fd(map);
 out:
	return map_fd;
}

/* BPF_MAP_TYPE_ARRAY */
void map_get_value_array(int fd, __u32 key, struct datarec *value)
{
	if ((bpf_map_lookup_elem(fd, &key, value)) != 0) {
		fprintf(stderr,
			"ERR: bpf_map_lookup_elem failed key:0x%X\n", key);
	}
}

/* BPF_MAP_TYPE_PERCPU_ARRAY */
void map_get_value_percpu_array(int fd, __u32 key, struct datarec *value)
{
	/* For percpu maps, userspace gets a value per possible CPU */
	// unsigned int nr_cpus = bpf_num_possible_cpus();
	// struct datarec values[nr_cpus];

	fprintf(stderr, "ERR: %s() not impl. see assignment#3", __func__);
}

static bool map_collect(int fd, __u32 map_type, __u32 key, struct record *rec)
{
	struct datarec value;

	switch (map_type) {
	case BPF_MAP_TYPE_ARRAY:
		map_get_value_array(fd, key, &value);
		break;
	case BPF_MAP_TYPE_PERCPU_ARRAY:
		/* fall-through */
	default:
		fprintf(stderr, "ERR: Unknown map_type(%u) cannot handle\n",
			map_type);
		return false;
		break;
	}

	/* Add byte counters */
	rec->total.rx_pkt_cnt = value.rx_pkt_cnt;
	rec->total.accu_rx_timestamp = value.accu_rx_timestamp;
	rec->total.sampleCounter = value.sampleCounter;
	//fprintf(stderr, "Packet Counter %x accu tx %lx channels %x\n", value.rx_pkt_cnt, value.accu_rx_timestamp, value.sampleCounter);
	return true;
}

/* It is userspace responsibility to known what map it is reading and
 * know the value size. Here get bpf_map_info and check if it match our expected
 * values.
 */
static int __check_map_fd_info(int map_fd, struct bpf_map_info *info,
			       struct bpf_map_info *exp)
{
	__u32 info_len = sizeof(*info);
	int err;

	if (map_fd < 0)
		return EXIT_FAIL;

        /* BPF-info via bpf-syscall */
	err = bpf_obj_get_info_by_fd(map_fd, info, &info_len);
	if (err) {
		fprintf(stderr, "ERR: %s() can't get info - %s\n",
			__func__,  strerror(errno));
		return EXIT_FAIL_BPF;
	}

	if (exp->key_size && exp->key_size != info->key_size) {
		fprintf(stderr, "ERR: %s() "
			"Map key size(%d) mismatch expected size(%d)\n",
			__func__, info->key_size, exp->key_size);
		return EXIT_FAIL;
	}
	if (exp->value_size && exp->value_size != info->value_size) {
		fprintf(stderr, "ERR: %s() "
			"Map value size(%d) mismatch expected size(%d)\n",
			__func__, info->value_size, exp->value_size);
		return EXIT_FAIL;
	}
	if (exp->max_entries && exp->max_entries != info->max_entries) {
		fprintf(stderr, "ERR: %s() "
			"Map max_entries(%d) mismatch expected size(%d)\n",
			__func__, info->max_entries, exp->max_entries);
		return EXIT_FAIL;
	}
	if (exp->type && exp->type  != info->type) {
		fprintf(stderr, "ERR: %s() "
			"Map type(%d) mismatch expected type(%d)\n",
			__func__, info->type, exp->type);
		return EXIT_FAIL;
	}

	return 0;
}
#endif // AVB_XDP




static void help()
{
	fprintf(stderr, "\n"
		"Usage: jack_listener [-h] -i interface -f file_name.wav"
		"\n"
		"Options:\n"
		"    -h  show this message\n"
		"    -i  specify interface for AVB connection\n"
		"\n" "%s" "\n", version_str);
	exit(EXIT_FAILURE);
}

void shutdown_and_exit(int sig)
{
	int ret;

	if (sig != 0)
		fprintf(stdout,"Received signal %d:", sig);
	fprintf(stdout,"Leaving...\n");

	if (0 != ctx_sig->talker) {
		ret = send_leave(ctx_sig);
		if (ret)
			printf("send_leave failed\n");
	}

	ret = mrp_disconnect(ctx_sig);
	if (ret)
		printf("mrp_disconnect failed\n");

	close(ctx_sig->control_socket);

	if (NULL != client) {
		fprintf(stdout, "jack\n");
		jack_client_close(client);
		jack_ringbuffer_free(ringbuffer);
	}

	if (sig != 0)
		exit(EXIT_SUCCESS); /* actual signal */
	else
		exit(EXIT_FAILURE); /* fail condition */
}







int receive_avtp_packet(
#ifdef AVB_XDP
                        int fd, __u32 map_type, struct stats_rec *record
#endif
                        )
{
    char stream_packet[BUFLEN];

	uint32_t* mybuf;
	uint32_t frame[CHANNELS];
	jack_default_audio_sample_t jackframe[CHANNELS];
	int cnt;
	static int total;

    struct msghdr msg;
    struct cmsghdr *cmsg;
    struct sockaddr_ll remote;
    struct iovec sgentry;
    struct {
        struct cmsghdr cm;
        char control[256];
    } control;

    memset( &msg, 0, sizeof( msg ));
    msg.msg_iov = &sgentry;
    msg.msg_iovlen = 1;
    sgentry.iov_base = stream_packet;
    sgentry.iov_len = BUFLEN;

    memset( &remote, 0, sizeof(remote));
    msg.msg_name = (caddr_t) &remote;
    msg.msg_namelen = sizeof( remote );
    msg.msg_control = &control;
    msg.msg_controllen = sizeof(control);

    int status = recvmsg(avtp_transport_socket_fds->fd, &msg, 0);//NULL);

    if (status == 0) {
        fprintf(stdout, "EOF\n");fflush(stdout);
        return -1;
    } else if (status < 0) {
        fprintf(stdout, "Error recvmsg: %d %d %s\n", status, errno, strerror(errno));fflush(stdout);
        return -1;
    }

#ifdef AVB_XDP

    uint64_t packet_arrival_time_ns = 0;
       // Packet Arrival Time from Device
    cmsg = CMSG_FIRSTHDR(&msg);
    while( cmsg != NULL ) {
        if( cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SO_TIMESTAMPING ) {
            struct timespec *ts_device, *ts_system;
            ts_system = ((struct timespec *) CMSG_DATA(cmsg)) + 1;
            ts_device = ts_system + 1;
            packet_arrival_time_ns =  (ts_device->tv_sec*1000000000LL + ts_device->tv_nsec);
            break;
        }
        cmsg = CMSG_NXTHDR(&msg,cmsg);
    }
        
        
    /* Collect other XDP actions stats  */
    __u32 key = XDP_PASS;
    map_collect(fd, map_type, key, &record->stats[0]);

    struct record *rec;
    const char *action = action2str(XDP_PASS);
    rec  = &record->stats[0];


    fprintf(stdout, "RxTimestamp %lx\n", packet_arrival_time_ns);

    mybuf = (uint32_t*) (stream_packet + HEADER_SIZE);

//    memcpy(&frame[0], &rec, sizeof(frame));





    for(int i = 0; i < SAMPLES_PER_FRAME * CHANNELS; i+=CHANNELS) {
        for(int j = 0; j < CHANNELS; j++) {

            frame[j] = ntohl(frame[j]);   /* convert to host-byte order */
            frame[j] &= 0x00ffffff;       /* ignore leading label */
            frame[j] <<= 8;               /* left-align remaining PCM-24 sample */

            jackframe[j] = ((int32_t)frame[j])/(float)(MAX_SAMPLE_VALUE);
        }

        if ((cnt = jack_ringbuffer_write_space(ringbuffer)) >= SAMPLE_SIZE * CHANNELS) {
            jack_ringbuffer_write(ringbuffer, (void*)&jackframe[0], SAMPLE_SIZE * CHANNELS);
//			fprintf(stdout, "Wrote %d bytes after %i samples.\n", SAMPLE_SIZE * CHANNELS, total);
        } else {
            fprintf(stdout, "Only %i bytes available after %i samples.\n", cnt, total);
        }

        if (jack_ringbuffer_write_space(ringbuffer) <= SAMPLE_SIZE * CHANNELS * DEFAULT_RINGBUFFER_SIZE / 4) {
            /** Ringbuffer has only 25% or less write space available, it's time to tell jackd
            to read some data. */
            ready = 1;
        }
    }
    
    
    
    
    
    
    
#else
    if( // Compare Stream IDs
        (glob_stream_id[0] == (uint8_t) stream_packet[18]) &&
        (glob_stream_id[1] == (uint8_t) stream_packet[19]) &&
        (glob_stream_id[2] == (uint8_t) stream_packet[20]) &&
        (glob_stream_id[3] == (uint8_t) stream_packet[21]) &&
        (glob_stream_id[4] == (uint8_t) stream_packet[22]) &&
        (glob_stream_id[5] == (uint8_t) stream_packet[23]) &&
        (glob_stream_id[6] == (uint8_t) stream_packet[24]) &&
        (glob_stream_id[7] == (uint8_t) stream_packet[25])
    ){
        mybuf = (uint32_t*) (stream_packet + HEADER_SIZE);

        for(int i = 0; i < SAMPLES_PER_FRAME * CHANNELS; i+=CHANNELS) {

            memcpy(&frame[0], &mybuf[i], sizeof(frame));

            for(int j = 0; j < CHANNELS; j++) {

                frame[j] = ntohl(frame[j]);   /* convert to host-byte order */
                frame[j] &= 0x00ffffff;       /* ignore leading label */
                frame[j] <<= 8;               /* left-align remaining PCM-24 sample */

                jackframe[j] = ((int32_t)frame[j])/(float)(MAX_SAMPLE_VALUE);
            }

            if ((cnt = jack_ringbuffer_write_space(ringbuffer)) >= SAMPLE_SIZE * CHANNELS) {
                jack_ringbuffer_write(ringbuffer, (void*)&jackframe[0], SAMPLE_SIZE * CHANNELS);
    //			fprintf(stdout, "Wrote %d bytes after %i samples.\n", SAMPLE_SIZE * CHANNELS, total);
            } else {
                fprintf(stdout, "Only %i bytes available after %i samples.\n", cnt, total);
            }

            if (jack_ringbuffer_write_space(ringbuffer) <= SAMPLE_SIZE * CHANNELS * DEFAULT_RINGBUFFER_SIZE / 4) {
                /** Ringbuffer has only 25% or less write space available, it's time to tell jackd
                to read some data. */
                ready = 1;
            }

        }
    }
#endif // AVB_XDP






    return 0;
}



static int process_jack(jack_nframes_t nframes, void* arg)
{
	(void) arg; /* unused */

	if (!ready) {
		return 0;
	}

	for(int i = 0; i < CHANNELS; i++) {
		out[i] = jack_port_get_buffer(outputports[i], nframes);
	}

	for(size_t i = 0; i < nframes; i++) {

		if (jack_ringbuffer_read_space(ringbuffer) >= SAMPLE_SIZE * CHANNELS) {

			for(int j = 0; j < CHANNELS; j++){
				jack_ringbuffer_read (ringbuffer, (char*)(out[j]+i), SAMPLE_SIZE);
			}

		} else {
			//printf ("underrun\n");
			ready = 0;

			return 0;
		}
	}

	return 0;
}

void jack_shutdown(void* arg)
{
	(void)arg; /* unused*/

	printf("JACK shutdown\n");
	shutdown_and_exit(0);
}

jack_client_t* init_jack(struct mrp_listener_ctx *ctx)
{
	const char* client_name = "simple_listener";
	const char* server_name = "AVB_Processing";
	jack_options_t options = JackNoStartServer | JackUseExactName | JackServerName;
	jack_status_t status;

	client = jack_client_open (client_name, options, &status, server_name);

	if (NULL == client) {
		fprintf (stderr, "jack_client_open() failed\n ");
		shutdown_and_exit(0);
	}

	if (status & JackServerStarted) {
		fprintf (stderr, "JACK server started\n");
	}

	if (status & JackNameNotUnique) {
		client_name = jack_get_client_name(client);
		fprintf (stderr, "unique name `%s' assigned\n", client_name);
	}

	jack_set_process_callback(client, process_jack, (void *)ctx);
	jack_on_shutdown(client, jack_shutdown, (void *)ctx);

	outputports = (jack_port_t**) malloc (CHANNELS * sizeof (jack_port_t*));
	int nframes = jack_get_buffer_size(client);
	out = (jack_default_audio_sample_t**) malloc (CHANNELS * sizeof (jack_default_audio_sample_t*));
	ringbuffer = jack_ringbuffer_create (SAMPLE_SIZE * DEFAULT_RINGBUFFER_SIZE * CHANNELS);
	jack_ringbuffer_mlock(ringbuffer);

	memset(out, 0, sizeof (jack_default_audio_sample_t*)*CHANNELS);
	memset(ringbuffer->buf, 0, ringbuffer->size);

	for(int i = 0; i < CHANNELS; i++) {

		char* portName;
		if (asprintf(&portName, "output%d", i) < 0) {
			fprintf(stderr, "could not create portname for port %d\n", i);
			shutdown_and_exit(0);
		}

		outputports[i] = jack_port_register (client, portName, JACK_DEFAULT_AUDIO_TYPE, JackPortIsOutput, 0);
		if (NULL == outputports[i]) {
			fprintf (stderr, "cannot register output port \"%d\"!\n", i);
			shutdown_and_exit(0);
		}
	}

	const char** ports;
	if (jack_activate (client)) {
		fprintf (stderr, "cannot activate client\n");
		shutdown_and_exit(0);
	}

	return client;
}




int main(int argc, char *argv[])
{
	char* dev = NULL;
	int dstStreamUId = -1;
	int dstEndpointId = -1;

    avtp_transport_socket_fds = (struct pollfd*)malloc(sizeof(struct pollfd));
    memset(avtp_transport_socket_fds, 0, sizeof(avtp_transport_socket_fds));

	int rc;
	struct mrp_listener_ctx *ctx = malloc(sizeof(struct mrp_listener_ctx));
	struct mrp_domain_attr *class_a = malloc(sizeof(struct mrp_domain_attr));
	struct mrp_domain_attr *class_b = malloc(sizeof(struct mrp_domain_attr));
	ctx_sig = ctx;
	signal(SIGINT, shutdown_and_exit);

	int c;
	while((c = getopt(argc, argv, "hi:s:e:")) > 0)	{
		switch (c)		{
            case 'h':
                help();
                break;
            case 'i':
                dev = strdup(optarg);
                break;
            case 's':
                dstStreamUId = atoi(optarg);
                break;
            case 'e':
                dstEndpointId = atoi(optarg);
                break;
            default:
                    fprintf(stderr, "Unrecognized option!\n");
		}
	}

	if (NULL == dev || -1 == dstStreamUId || -1 == dstEndpointId) {
		help();
	}
	
	
#ifdef AVB_XDP
	struct bpf_map_info map_expect = { 0 };
	struct bpf_map_info info = { 0 };
	struct bpf_object *bpf_obj;
	int stats_map_fd;
    struct stats_rec stats_record;
	int interval = 2;
	int err;

	struct config cfg = {
		.xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_SKB_MODE,
		.ifindex   = -1,
		.do_unload = true,
	};
	cfg.xsk_bind_flags &= XDP_ZEROCOPY;
    cfg.xsk_bind_flags |= XDP_COPY;
	
	/* Set default BPF-ELF object file and BPF program name */
	strncpy(cfg.filename, default_filename, sizeof(cfg.filename));
	strncpy(cfg.progsec,  default_progsec,  sizeof(cfg.progsec));
	
    if (strlen(dev) >= IF_NAMESIZE) {
        fprintf(stderr, "ERR: --dev name too long\n");
    }
    cfg.ifname = (char *)&cfg.ifname_buf;
    strncpy(cfg.ifname, dev, IF_NAMESIZE);
    cfg.ifindex = if_nametoindex(cfg.ifname);
    if (cfg.ifindex == 0) {
        fprintf(stderr,
	        "ERR: --dev name unknown err(%d):%s\n",
	        errno, strerror(errno));
    }
    
	if (cfg.do_unload)
		xdp_link_detach(cfg.ifindex, cfg.xdp_flags, 0);
	
    bpf_obj = load_bpf_and_xdp_attach(&cfg);
	if (!bpf_obj)
		return EXIT_FAIL_BPF;


	/* Locate map file descriptor */
	stats_map_fd = find_map_fd(bpf_obj, "xdp_stats_map");
	if (stats_map_fd < 0) {
		xdp_link_detach(cfg.ifindex, cfg.xdp_flags, 0);
		return EXIT_FAIL_BPF;
	}

	/* check map info, e.g. datarec is expected size */
	map_expect.key_size    = sizeof(__u32);
	map_expect.value_size  = sizeof(struct datarec);
	map_expect.max_entries = XDP_ACTION_MAX;
	err = __check_map_fd_info(stats_map_fd, &info, &map_expect);
	if (err) {
		fprintf(stderr, "ERR: map via FD not compatible\n");
		return err;
	}
	if (verbose) {
		printf("\nCollecting stats from BPF map\n");
		printf(" - BPF map (bpf_map_type:%d) id:%d name:%s"
		       " key_size:%d value_size:%d max_entries:%d\n",
		       info.type, info.id, info.name,
		       info.key_size, info.value_size, info.max_entries
		       );
	}

    /* Collect other XDP actions stats  */
    __u32 key = XDP_PASS;
    map_collect(stats_map_fd, info.type, key, &stats_record.stats[0]);

#endif


	rc = mrp_listener_client_init(ctx);
	if (rc)
	{
		printf("failed to initialize global variables\n");
		return EXIT_FAILURE;
	}


	/*
        Set Dest MAC
	*/

	glob_dest_addr[4] = dstStreamUId;
	glob_dest_addr[5] = dstEndpointId;

	glob_station_addr[4] = dstStreamUId;
	glob_station_addr[5] = dstEndpointId;

	memset(glob_stream_id, 0, sizeof(glob_stream_id));
	memcpy(glob_stream_id, glob_station_addr, sizeof(glob_station_addr));
	memcpy(ctx->stream_id, glob_stream_id, sizeof(glob_stream_id));
	memcpy(ctx->dst_mac, glob_dest_addr, sizeof(glob_dest_addr));

	printf("Stream ID: %02x%02x%02x%02x%02x%02x%02x%02x\n",
                                     ctx->stream_id[0], ctx->stream_id[1],
                                     ctx->stream_id[2], ctx->stream_id[3],
                                     ctx->stream_id[4], ctx->stream_id[5],
                                     ctx->stream_id[6], ctx->stream_id[7]);
	printf("Dest MAC: %02x%02x%02x%02x%02x%02x\n",
                                     glob_dest_addr[0], glob_dest_addr[1],
                                     glob_dest_addr[2], glob_dest_addr[3],
                                     glob_dest_addr[4], glob_dest_addr[5]);

    fprintf(stdout,  "create RAW AVTP Socket %s  \n", dev);fflush(stdout);

    if( create_RAW_AVB_Transport_Socket(stdout, &(avtp_transport_socket_fds->fd), dev) > RETURN_VALUE_FAILURE ){
        fprintf(stdout,  "enable IEEE1722 AVTP MAC filter %x:%x:%x:%x:%x:%x  \n",
                                                                                glob_dest_addr[0],
                                                                                glob_dest_addr[1],
                                                                                glob_dest_addr[2],
                                                                                glob_dest_addr[3],
                                                                                glob_dest_addr[4],
                                                                                glob_dest_addr[5]);fflush(stdout);

        enable_1722avtp_filter(stdout, avtp_transport_socket_fds->fd, glob_dest_addr);
        avtp_transport_socket_fds->events = POLLIN;
    } else {
        fprintf(stdout,  "Listener Creation failed\n");fflush(stdout);
    }

	if (create_socket(ctx)) {
		fprintf(stderr, "Socket creation failed.\n");
		return errno;
	}

	rc = mrp_monitor(ctx);
	if (rc)
	{
		printf("failed creating MRP monitor thread\n");
		return EXIT_FAILURE;
	}
	rc=mrp_get_domain(ctx, class_a, class_b);
	if (rc)
	{
		printf("failed calling mrp_get_domain()\n");
		return EXIT_FAILURE;
	}

	printf("detected domain Class A PRIO=%d VID=%04x...\n",class_a->priority,class_a->vid);

	rc = report_domain_status(class_a,ctx);
	if (rc) {
		printf("report_domain_status failed\n");
		return EXIT_FAILURE;
	}

	rc = join_vlan(class_a, ctx);
	if (rc) {
		printf("join_vlan failed\n");
		return EXIT_FAILURE;
	}

	init_jack(ctx);

	fprintf(stdout,"Waiting for talker...\n");
	await_talker(ctx);
	fprintf(stdout,"Found talker...\n");

	rc = send_ready(ctx);
	if (rc) {
		printf("send_ready failed\n");
		return EXIT_FAILURE;
	}






    while(!ctx->halt_tx){

        receive_avtp_packet(
#ifdef AVB_XDP
                            stats_map_fd, info.type, &stats_record
#endif
                            );

    }




	usleep(-1);
	free(avtp_transport_socket_fds);
	free(ctx);
	free(class_a);
	free(class_b);

	return EXIT_SUCCESS;
}
