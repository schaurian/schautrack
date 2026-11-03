/**
 * The containers the suite reads from and writes to, named explicitly.
 *
 * These used to be discovered with `docker ps | grep schautrack.*db`, which
 * picks ANY running schautrack database — a dev stack, or another checkout's
 * test stack — and the seed then rewrote and wiped that database's users. The
 * names are now derived from the compose project instead, the same way
 * `docker compose` derives them, so the suite only ever touches the stack it
 * was started against:
 *
 *   COMPOSE_PROJECT_NAME  the project (default: compose.test.yml's
 *                         `name: schautrack-test`); docker compose honours the
 *                         same variable, so setting it once moves both
 *   DB_CONTAINER          override the database container outright
 *   E2E_WEB_CONTAINER     override the web container outright
 *
 * To seed the dev stack instead: COMPOSE_PROJECT_NAME=schautrack-dev.
 */
const PROJECT = process.env.COMPOSE_PROJECT_NAME || 'schautrack-test';

export const DB_CONTAINER = process.env.DB_CONTAINER || `${PROJECT}-db-1`;
export const WEB_CONTAINER = process.env.E2E_WEB_CONTAINER || `${PROJECT}-web-1`;
