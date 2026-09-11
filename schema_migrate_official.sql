-- Mail written by the support desk itself is marked; anything arriving from
-- outside stays 0, so a forged From cannot earn the verified mark.
ALTER TABLE messages ADD COLUMN official INTEGER NOT NULL DEFAULT 0;
