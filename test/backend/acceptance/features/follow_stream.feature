@tshark
Feature: Follow stream
  Following a stream shows the reassembled payload of a conversation, split
  by direction, from any packet in it (brief 4.5, acceptance criterion 5).

  Scenario: Follow a TCP stream from a selected packet
    Given the capture "http.pcap" is open
    When I follow the "tcp" stream of packet 4
    Then the followed stream is number 0 between "192.168.1.10:50000" and "93.184.216.34:80"
    And the client sent 90 bytes and the server sent 491 bytes
    And the client data starts with "GET /index.html HTTP/1.1"
    And the server data starts with "HTTP/1.1 200 OK"
    And the stream filter is "tcp.stream eq 0"

  Scenario: Follow a UDP stream
    Given the capture "dns.pcap" is open
    When I follow the "udp" stream of packet 1
    Then the client sent 29 bytes and the server sent 56 bytes

  Scenario: Follow an HTTP stream by number
    Given the capture "http.pcap" is open
    When I follow "http" stream number 0
    Then the server data starts with "HTTP/1.1 200 OK"

  Scenario: A packet outside any TCP stream
    Given the capture "mixed.pcapng" is open
    When I follow the "tcp" stream of packet 1
    Then the request fails with "not part of a TCP stream"

  Scenario: TLS without keys explains why nothing is shown
    Given the capture "tls.pcap" is open
    When I follow the "tls" stream of packet 4
    Then the followed stream is empty
    And the follow hint mentions "tls.keylog_file"

  Scenario: Follow an HTTP/2 stream from a packet: its own sub-stream
    Given the capture "streams.pcapng" is open
    When I follow the "http2" stream of packet 12
    Then the followed stream is number 0 between "192.168.1.10:50100" and "192.168.1.20:8080"
    And the sub-streams are 0, 1 and 3, following 3
    And the client data contains "/two.txt"
    And the server data contains "second stream body"

  Scenario: Follow another HTTP/2 sub-stream by number
    Given the capture "streams.pcapng" is open
    When I follow "http2" stream number 0 sub-stream 1
    Then the client data contains "/one.txt"
    And the server data contains "first stream body"

  Scenario: A TCP stream without HTTP/2
    Given the capture "streams.pcapng" is open
    When I follow "http2" stream number 1
    Then the followed stream is empty
    And the follow hint mentions "Decode As"

  Scenario: Follow a WebSocket conversation: the messages, unmasked
    Given the capture "streams.pcapng" is open
    When I follow the "websocket" stream of packet 24
    Then the followed stream is number 1 between "192.168.1.10:50200" and "192.168.1.30:80"
    And the client sent 12 bytes and the server sent 12 bytes
    And the client data starts with "hello server"
    And the server data starts with "hello client"

  Scenario: Follow a QUIC stream decrypted with the keys stored in the capture
    Given the capture "streams.pcapng" is open
    When I follow the "quic" stream of packet 33
    Then the followed stream is number 0 between "10.0.0.1:50300" and "10.0.0.2:443"
    And the sub-streams are 0 and 4, following 0
    And the client data starts with "GET /hello.txt"
    And the server data starts with "Hello over QUIC!"

  Scenario: A QUIC stream carrying data one way
    Given the capture "streams.pcapng" is open
    When I follow "quic" stream number 0 sub-stream 4
    Then the client sent 19 bytes and the server sent 0 bytes

  Scenario: A packet outside any QUIC connection
    Given the capture "streams.pcapng" is open
    When I follow the "quic" stream of packet 1
    Then the request fails with "not part of a QUIC connection"
