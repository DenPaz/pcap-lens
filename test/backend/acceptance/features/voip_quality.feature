@tshark
Feature: VoIP call quality with packet loss
  The quality estimate follows the worst stream of a call: one lost packet
  in 50 brings a G.711 call from Best down to High.

  Background:
    Given the capture "voip.pcap" is open

  Scenario: A lost packet lowers the call's rating
    When I list the VoIP calls
    Then call 1 is rated High with a MOS of 4.23
    And the RTP stream from "10.0.0.2:50000" is rated Best with a MOS of 4.4
    And call 1 rang after 0.05 s, was answered after 1.0 s and lasted 1.07 s
    And call 1 was ended by the caller
    And call 2 was ended by the callee
