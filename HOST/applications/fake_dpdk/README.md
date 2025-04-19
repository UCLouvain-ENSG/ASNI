# ASQ & IO abstractions

This is a small documentation to explain how we abstracted IO (DPDK & XCHG) and ASQ behind a single API.

## Abstracting IO

Globally, the API looks like this :

```c
/**
 * Previously initialized variables :
 * 
 * - port : The port to listen to
 * - queue : The queue to listen to
 * - out_port : The port to sent to
 * - out_queue : The queue to sent to
 * - BATCH_SIZE : size of a batch
*/

// Initializes a state struct to hides inner working of IO
FAKE_DPDK_IO_INIT(state);
while (1){
    // Receives a burst, and creates variables descriptors and rx_count
    FAKE_DPDK_IO_RX_BURST(port, queue, descriptors, BATCH_SIZE, rx_count, state);
    // You can then iterate over packets
    for (uint16_t n = 0; n < rx_count; n++) {
        // Setup metadata, it is handled by the API and not a concern for users
        FAKE_DPDK_IO_SETUP_METADATA(descriptors[n], rx_count, metadata);
        // Retrieve pointer to payload
        uint8_t *data;
        FAKE_DPDK_IO_GET_PAYLOAD_PTR(descriptors[n], data);
        // Do some application specific processing
        // Suppose that shouldIForward returns 0
        // if the packet should be dropped, 1 otherwise
        uint8_t decision = shouldIForward(data);
        // Enqueue if necessary
        if (decision){
            uint16_t size;
            FAKE_DPDK_IO_GET_IMPLICIT_PAYLOAD_SIZE(descriptors[n], size);
            uint8_t *payload;
            FAKE_DPDK_IO_GET_IMPLICIT_PAYLOAD_PTR(descriptors[n], payload);
            FAKE_DPDK_IO_TX_ENQUEUE(state, descriptors[n], subdescriptors[sub_desc].size, metadata, payload);
        } else {
            // Free if possible
            FAKE_DPDK_IO_FREE_IMPLICIT(descriptors[n]);
        }
        // Allows the API to understand that you don't need the packet anymore
        FAKE_DPDK_IO_END_PROCESS(descriptors[n]);
    }
    // Send enqueued packets and creates the tx_count variable
    FAKE_DPDK_IO_TX_BURST(out_port, out_queue, rx_count, tx_count, state);
    print("Sent %u packets\n", tx_count);
}
```