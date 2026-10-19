@tshark
Feature: VoIP audio codecs and RTCP
  Streams in G.722, G.726-32 (a dynamic payload type the SDP maps) and L16
  can be played and saved, and what the receivers' RTCP reports said about
  each stream is shown with it.

  Background:
    Given the capture "voip-media.pcap" is open

  Scenario Outline: Each codec decodes
    When I list the VoIP calls
    And I save the audio of the RTP stream from "<source>"
    Then the file is decoded as <codec> at <rate> Hz

    Examples:
      | source         | codec    | rate  |
      | 10.0.1.7:46000 | G.722    | 16000 |
      | 10.0.1.2:48000 | G.726-32 | 8000  |
      | 10.0.1.8:50000 | L16      | 8000  |

  Scenario: RTCP reports
    When I list the VoIP calls
    Then RTCP from 10.0.1.7 says the RTP stream from "10.0.1.2:48000" lost 10.2% with a round trip of about 40 ms
    And the RTP stream from "10.0.1.8:50000" has no RTCP reports
