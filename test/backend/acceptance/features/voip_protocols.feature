@tshark
Feature: H.323, MGCP and IAX2 calls
  Besides SIP, the VoIP panel lists the calls set up with H.323, MGCP and
  IAX2, links each to its media (RTP, or IAX2's own voice frames) and gives
  it the same details: timings, who hung up and why, DTMF digits, quality,
  media problems, its filter and its audio.

  Background:
    Given the capture "voip-other.pcap" is open

  Scenario: Calls of every protocol, in the order they started
    When I list the VoIP calls
    Then there are 7 calls and 7 media streams
    And the calls use H.323, H.323, H.323, IAX2, IAX2, MGCP and MGCP

  Scenario: H.323 calls
    When I list the VoIP calls
    Then call 1 goes from "alan <1001>" to "2002" and is Completed
    And call 1 has the messages Setup, Call Proceeding, Alerting, Connect, Facility: OpenLogicalChannel, Facility: OpenLogicalChannelAck, Facility: OpenLogicalChannel, Facility: OpenLogicalChannelAck, Facility: UserInputIndication and Release Complete
    And call 1 rang after 0.1 s, was answered after 0.8 s and lasted 1.2 s
    And call 1 was ended by the caller with "Q.850 cause 16: Normal call clearing"
    And call 1 has the DTMF digits 5
    And call 1 has 2 media streams
    And call 2 has the messages Setup (fast start), Alerting, Connect, OpenLogicalChannel, OpenLogicalChannelAck, EndSessionCommand and Release Complete
    And call 2 has the media problems one-way
    And call 3 goes from "alan <1001>" to "2002" and is Rejected with "User busy"

  Scenario: IAX2 calls and their voice
    When I list the VoIP calls
    Then call 4 goes from "Mike <3001>" to "4001@default" and is Completed
    And call 4 has the messages NEW, ACCEPT, RINGING, ANSWER, DTMF 7 and HANGUP
    And call 4 was ended by the callee with "Q.850 cause 16: Normal Clearing"
    And call 4 has 2 media streams
    And call 5 goes from "3002" to "9999" and is Rejected with "No such context/extension"
    When I save the audio of call 4
    Then the file is stereo 8000 Hz audio with a 440 Hz tone on the left and a 880 Hz tone on the right

  Scenario: MGCP calls
    When I list the VoIP calls
    Then call 6 goes from "aaln/1@gw1.example.net" to "aaln/1@gw2.example.net" and is Completed
    And call 6 rang after 0.8 s, was answered after 2.0 s and lasted 1.2 s
    And call 6 was ended by the caller
    And call 6 dialled 2002
    And call 6 has 2 media streams
    And call 7 goes from "aaln/1@gw2.example.net" to "aaln/1@gw1.example.net" and is Rejected with "401 Phone off hook"
    When I apply the filter of call 6
    Then 124 packets are displayed
