import 'dart:convert';
import 'dart:typed_data';

import 'package:esp_smartconfig/esp_smartconfig.dart';
import 'package:esp_smartconfig/src/protocols/esptouch.dart';
import 'package:test/test.dart';

void main() {
  const bssid = 'a8:2b:d6:12:34:56';
  const bssidBytes = [0xa8, 0x2b, 0xd6, 0x12, 0x34, 0x56];

  void verifyPackets(String ssid, String? password) {
    final request = ProvisioningRequest.fromStrings(
        ssid: ssid, bssid: bssid, password: password);
    final protocol = EspTouch()..request = request;
    protocol.prepare();

    final ssidBytes = utf8.encode(ssid);
    final passwordBytes = password == null ? <int>[] : utf8.encode(password);
    final totalLength = 9 + passwordBytes.length + ssidBytes.length;

    expect(protocol.blocks.take(4), [515, 514, 513, 512]);
    expect(
        protocol.blocks, hasLength(4 + (totalLength + bssidBytes.length) * 3));

    // Decode transmitted packet lengths back into indexed credential bytes.
    final decoded = <int, int>{};
    for (var offset = 4; offset < protocol.blocks.length; offset += 3) {
      final index = protocol.blocks[offset + 1] - 40 - 0x100;
      final high = (protocol.blocks[offset] - 40) & 0x0f;
      final low = (protocol.blocks[offset + 2] - 40) & 0x0f;
      expect(decoded.containsKey(index), isFalse,
          reason: 'Duplicate data index $index');
      decoded[index] = (high << 4) | low;
    }

    expect(
        decoded.keys,
        unorderedEquals(
            List.generate(totalLength + bssidBytes.length, (index) => index)));
    expect(decoded[0], totalLength);
    expect(decoded[1], passwordBytes.length);
    expect([for (var index = 9; index < totalLength; index++) decoded[index]],
        [...passwordBytes, ...ssidBytes]);
    expect([
      for (var index = totalLength; index < totalLength + 6; index++)
        decoded[index]
    ], bssidBytes);
    if (password == null) expect(request.password, isNull);

    final response = protocol.receive(
        Uint8List.fromList([totalLength, ...bssidBytes, 192, 168, 1, 10]));
    expect(response.bssidText, bssid);
    expect(response.ipAddressText, '192.168.1.10');
  }

  group('비밀번호 없는 Wi-Fi', () {
    for (var length = 1; length <= 32; length++) {
      test('$length바이트 SSID의 패킷과 응답을 처리한다', () {
        verifyPackets('a' * length, null);
      });
    }

    test('한글 SSID를 UTF-8로 전송한다', () {
      verifyPackets('시하스', null);
    });
  });

  group('비밀번호 있는 Wi-Fi', () {
    test('짧은 SSID와 최소 길이 비밀번호를 전송한다', () {
      verifyPackets('a', '12345678');
    });

    test('비밀번호의 공백을 보존한다', () {
      verifyPackets('SiHAS WiFi', ' password ');
    });

    test('최대 길이 SSID와 비밀번호를 전송한다', () {
      verifyPackets('a' * 32, 'p' * 64);
    });
  });
}
