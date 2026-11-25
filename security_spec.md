# RoohCloud Firestore Security Specification

## 1. Data Invariants
1. Every `/users/{userId}` document can only be read or written by the authenticated, email-verified user whose `request.auth.uid == userId`.
2. Every `/users/{userId}/files/{fileId}` document belongs strictly to `{userId}` (`ownerId == userId == request.auth.uid`), with verified email (`request.auth.token.email_verified == true`), and immutable `fileId`, `ownerId`, and `createdAt`.
3. Every string field has strict `.size()` bounds and IDs match `^[a-zA-Z0-9_-]+$`.
4. No plaintext Rooh Key or unencrypted private key material is ever permitted in Firestore; only public salts and encrypted metadata are stored.
5. `createdAt` and `updatedAt` are strictly validated against `request.time`.

## 2. The "Dirty Dozen" Adversarial Payloads
1. **Shadow User Write**: Creating `/users/victim` while authenticated as `attacker`.
2. **Unverified Email Write**: Creating `/users/attacker` with `email_verified == false`.
3. **Ghost Field Injection on User**: Creating `/users/attacker` with extra field `isAdmin: true`.
4. **Oversized ID Poisoning**: Creating `/users/attacker/files/<1500-char-id>` to exhaust resources.
5. **Owner Spoofing on File**: Creating `/users/attacker/files/f1` with `ownerId: "victim"`.
6. **Timestamp Forgery**: Creating `/users/attacker/files/f1` with `createdAt` set to past date instead of `request.time`.
7. **Immutable Field Mutation**: Updating `ownerId` or `createdAt` on `/users/attacker/files/f1`.
8. **Type Poisoning on Update**: Updating `originalSize` on `/users/attacker/files/f1` to a string `"999"`.
9. **Invalid Provider Enum**: Creating `/users/attacker/files/f1` with `provider: "arbitrary-s3"`.
10. **PII Cross-User Read**: Reading `/users/victim` while authenticated as `attacker`.
11. **Blanket List Scraping**: Listing `/users` or `/users/victim/files` as `attacker`.
12. **Shadow Field Update on File**: Updating `/users/attacker/files/f1` with unexpected field `publicShareOverride: true`.
