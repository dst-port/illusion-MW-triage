-- Osquery example: find files in /tmp or /usr/bin with same basename as common utilities but different SHA256
-- Replace the whitelist table or join with your inventory to check expected hashes.

SELECT path, sha256, basename(path) as name
FROM file
WHERE name IN ('bash','sshd','sudo','systemd','python','python3')
  AND (sha256 IS NOT NULL)
ORDER BY name;

-- You can join against a `whitelist` table with expected sha256 to find mismatches:
-- SELECT f.path, f.sha256, w.expected_sha256 FROM file f JOIN whitelist w ON basename(f.path)=w.name WHERE f.sha256 != w.expected_sha256;
