SERVER_IP=10.0.0.1
CLIENT_IP=10.0.0.3

sudo killall etcd
rm -r client.etcd
etcd --name client \
	--initial-advertise-peer-urls http://${CLIENT_IP}:2380 \
	--listen-peer-urls http://${CLIENT_IP}:2380 \
	--listen-client-urls http://${CLIENT_IP}:2379,http://127.0.0.1:2379 \
	--advertise-client-urls http://${CLIENT_IP}:2379 --initial-cluster-token cluster-1 \
	--initial-cluster client=http://${CLIENT_IP}:2380,server=http://${SERVER_IP}:2380 \
	--initial-cluster-state new
