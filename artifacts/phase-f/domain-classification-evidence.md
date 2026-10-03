# Domain & Network Endpoint Classification Evidence

Phase F builds on Phase E network extraction to classify endpoints into functional categories while explicitly preserving raw endpoints and disclaiming unverified runtime transmission.

### Classified Categories:
- `first_party`: Domain matches the application's root package name
- `cdn`: Known content distribution networks (Cloudflare, AWS CloudFront, Fastly)
- `social_login`: Known authentication providers (GitHub, Google OAuth)
- `update_infrastructure`: Update checking and repository services (F-Droid, GitHub Releases)
- `potentially_sensitive`: Direct raw IP addresses or unencrypted HTTP authentication endpoints
- `unknown`: Endpoints without sufficient static evidence for functional categorization

## Summary of Endpoints by Category

- **`advertising`**: 1 distinct endpoints
- **`first_party`**: 2 distinct endpoints
- **`social_login`**: 1 distinct endpoints
- **`unknown`**: 9 distinct endpoints
- **`update_infrastructure`**: 7 distinct endpoints

## Static Network Evidence Disclaimer
> Static domain and URL extraction identifies referenced destinations in application bytecode and assets. It does not establish that network traffic is actively transmitted, received, or successfully connected at runtime without dynamic packet capture.
