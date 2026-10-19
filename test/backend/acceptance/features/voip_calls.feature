@tshark
Feature: VoIP call details
  For each SIP call the VoIP panel shows how long it rang and took to answer,
  who hung up and why, an estimate of its audio quality (E-model MOS), the
  DTMF digits sent, and media problems; one call can be filtered or saved
  on its own.

  Background:
    Given the capture "voip-calls.pcap" is open

  Scenario: Timings and how a call ended
    When I list the VoIP calls
    Then there are 5 SIP calls and 4 RTP streams
    And call 1 rang after 0.3 s, was answered after 1.5 s and lasted 2.1 s
    And call 1 was ended by the callee with "Q.850 cause 16: Normal call clearing"
    And call 4 was ended by the caller with "SIP 200: Call completed elsewhere"
    And call 5 goes from "ivan@10.0.1.6" to "erin@10.0.1.2" and is Rejected with "480 Temporarily Unavailable"
    And call 5 was ended by the callee with "Q.850 cause 18: No user responding"

  Scenario: Call quality
    When I list the VoIP calls
    Then call 1 is rated Best with a MOS of 4.4
    And call 3 has no quality rating

  Scenario: DTMF digits
    When I list the VoIP calls
    Then call 1 has the DTMF digits 4, 7 and #
    And the DTMF digit 7 of call 1 came in a SIP INFO and the others as RFC 4733 events

  Scenario: Media problems
    When I list the VoIP calls
    Then call 1 has no media problems
    And call 2 has the media problems one-way, codec, ssrc and gap
    And call 3 has the media problems no-rtp

  Scenario: One call alone
    When I list the VoIP calls
    And I apply the filter of call 1
    Then 209 packets are displayed
    When I export the packets of call 2 as pcapng
    Then the exported capture is a pcapng file with 56 packets
