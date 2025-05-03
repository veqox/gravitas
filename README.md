# gravitas

A dns server intended for self-hosting

> [!WARNING]
> This project is wip and far from being ready to be used in production.

## Roadmap

- [ ] Implement the basic dns protocol according to [rfc 1035](https://www.rfc-editor.org/rfc/rfc1035)
    - [x] Parse dns messages
    - [x] Serialize dns messages
    - [x] Support most common record types (A, AAAA, CNAME, MX, NS, PTR, SOA, TXT, SRV, etc.)
    - [x] Support domain name compression
    - [ ] Support tcp alongside udp
    - [ ] Support recursive query resolution
    - [ ] Support iterative query resolution
    - [ ] ...
- [ ] Add modern features like edns, dnssec [rfc 9499 (bcp)](https://www.rfc-editor.org/rfc/rfc9499)
