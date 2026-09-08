# Browser Secure DNS signal

The General settings DNS controls include an independent checkbox to disable
automatically enabled Secure DNS in Firefox. It uses the existing DNS signal,
not a list of blocked HTTPS resolver providers.

## Configuration and scope

`dns.firefox_doh_canary` is an optional boolean. Omitted, null and true retain
the previous behavior; false removes the panel-generated directive:

```text
address=/use-application-dns.net/
```

This makes the managed dnsmasq return NXDOMAIN for the canary when enabled.
It does not change upstream DNS, client port 53/853 enforcement, nftables or
iptables rules, VPN configuration, or HTTPS traffic. Disabling the option
removes only this directive; other DNS filters may still affect that domain.

## Browser limitations

- Firefox uses this network signal for automatically enabled DoH; a user's
  manually enabled DoH takes precedence. [Mozilla documentation](https://support.mozilla.org/en-US/kb/canary-domain-use-application-dnsnet).
- Chromium explicitly does not implement the Firefox canary mechanism.
  [Chromium DoH FAQ](https://www.chromium.org/developers/dns-over-https/).
- This option does not configure Chrome, Edge or Yandex Browser. Adjust their
  own Secure DNS setting when they bypass network DNS. Yandex documents a browser
  setting and a managed-device policy, not this canary; network-wide control of
  Yandex is therefore not claimed. [Yandex user setting](https://browser.yandex.ru/help/en/security/dnscrypt),
  [Yandex managed policy](https://browser.yandex.ru/support/browser-corporate/ru/policy/dns-over-https-mode).

The signal requires the browser's canary lookup to reach the managed DNS path.
It is not a generic DoH blocker and does not disable encryption between Keenetic
and its upstream DNS provider. Search/video traffic is not redirected or blocked
by this option.

## Apply and persistence

The checkbox edits the existing local form and uses normal Save/Apply. Reverting
to the original value clears semantic dirty state. The effective boolean is part
of the resolver hash, so changing it regenerates the managed resolver config
through the existing pipeline. Old/default configurations share the same effective
behavior; explicit false survives serialization and backup. No new timer, owner,
admission check, restart path or browser-management API is introduced.

RU/EN help names the actual supported browser and distinguishes automatic DoH
from a user-selected encrypted resolver. Local tests exercise both dnsmasq-ipset
and dnsmasq-nftset output/hash plus config and form persistence. This is local
implementation evidence, not router/browser acceptance of an installed IPK.
