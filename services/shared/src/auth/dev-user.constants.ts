/**
 * Centralized mock user constants for development authentication.
 *
 * These values must remain consistent across all services to prevent
 * foreign key constraint errors when creating records in development.
 *
 * @remarks
 * - The userId and organizationId are UUIDs that will be auto-created
 *   in the database on first API request via the DevAuthGuard.
 * - Only used when NODE_ENV !== 'production'
 */
export const DEV_USER = {
  userId: '8f88a42b-e799-455c-b68a-308d7d2e9aa4',
  organizationId: '8924f0c1-7bb1-4be8-84ee-ad8725c712bf',
  keycloakId: 'john-doe-keycloak-id',
  email: 'john.doe@example.com',
  firstName: 'John',
  lastName: 'Doe',
  displayName: 'John Doe',
} as const;

export type DevUser = typeof DEV_USER;
