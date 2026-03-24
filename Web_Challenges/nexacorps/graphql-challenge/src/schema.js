const { gql } = require('graphql-tag');

const typeDefs = gql`
  type Query {
    """Returns the profile of the currently authenticated user."""
    me: User

    """Retrieve the full employee directory. Requires authentication."""
    getEmployees: [Employee!]!

    """
    Search employees by name. Requires admin privileges.
    """
    searchEmployees(query: String!): [Employee!]!

    """Administrative dashboard overview. Requires admin privileges."""
    adminPanel: AdminPanel
  }

  type Mutation {
    """Authenticate and receive a JWT token."""
    login(username: String!, password: String!): AuthPayload

    """Register a new employee account."""
    register(username: String!, password: String!, email: String): AuthPayload

    """
    Update your profile information.
    Returns a refreshed token reflecting any profile changes.
    """
    updateProfile(input: UpdateProfileInput!): UpdateProfilePayload
  }

  # ─── Types ─────────────────────────────────────────────────────────────────

  type User {
    id: ID!
    username: String!
    email: String
    displayName: String
    bio: String
    role: String!
  }

  type Employee {
    id: ID!
    name: String!
    department: String!
    """Salary is only visible to admin users."""
    salary: Float
  }

  type AuthPayload {
    token: String!
    user: User!
  }

  type UpdateProfilePayload {
    """A newly-signed token reflecting updated profile data."""
    token: String!
    user: User!
  }

  type AdminPanel {
    totalUsers: Int!
    totalEmployees: Int!
    systemVersion: String!
  }

  # ─── Inputs ────────────────────────────────────────────────────────────────

  input UpdateProfileInput {
    displayName: String
    bio: String
    email: String
    """Internal field — do not use."""
    role: String
  }
`;

module.exports = { typeDefs };
