#include "mica/datagram/datagram_server.h"
#include "mica/util/lcore.h"

#ifdef USE_ASNI
struct ASNIConfig : public ::mica::network::BasicASNIConfig {
  static constexpr bool kVerbose = true;
};
#else
struct DPDKConfig : public ::mica::network::BasicDPDKConfig {
  static constexpr bool kVerbose = true;
};
#endif

struct PartitionsConfig : public ::mica::processor::BasicPartitionsConfig {
  static constexpr bool kSkipPrefetchingForRecentKeyHashes = false;
  // static constexpr bool kVerbose = true;
};

struct DatagramServerConfig
    : public ::mica::datagram::BasicDatagramServerConfig {
  typedef ::mica::processor::Partitions<PartitionsConfig> Processor;
  // static constexpr bool kVerbose = true;
};

typedef ::mica::datagram::DatagramServer<DatagramServerConfig> Server;

int main() {
  ::mica::util::lcore.pin_thread(0);

  auto config = ::mica::util::Config::load_file("server.json");

  Server::DirectoryClient dir_client(config.get("dir_client"));

  DatagramServerConfig::Processor::Alloc alloc(config.get("alloc"));
  DatagramServerConfig::Processor processor(config.get("processor"), &alloc);

  DatagramServerConfig::Network network(config.get("network"));
  network.start();

  Server server(config.get("server"), &processor, &network, &dir_client);
  server.run();

  network.stop();

  return EXIT_SUCCESS;
}
