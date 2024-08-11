// (C) 2022-2024 by folkert van heusden <mail@vanheusden.com>, released under Apache License v2.0

#include <WiFi.h>

#include "mdns.h"


mdns m;

void setup() {
	Serial.begin(115200);

        WiFi.hostname("myname");  // TODO adjust this

	WiFi.begin(" enter SSID here ", " enter wifi password here ");  // TODO you may want to adjust this

	while (WiFi.status() != WL_CONNECTED) {
		Serial.print('.');
		delay(100);
	}

	m.add_name(80, "myname._http._tcp.local");  // TODO adjust this
	m.begin();

	Serial.println(F("Go!"));
}

void loop() {
	// TODO do something useful here
}
