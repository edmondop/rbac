package roles_test

import (
	"github.com/edmondop/rbac/internal/roles"
	"github.com/stretchr/testify/suite"
	"testing"
)

type UserRoleManagementSuite struct {
	suite.Suite
	userRoleManager *roles.InMemoryUserRoleManager
}

func TestUserRoleManagement(t *testing.T) {
	suite.Run(t, new(UserRoleManagementSuite))
}

func (s *UserRoleManagementSuite) SetupTest() {
	userRoleManager := roles.NewInMemoryUserRoleManager()
	s.userRoleManager = &userRoleManager
}

func (s *UserRoleManagementSuite) TestAddUser() {
	added := s.userRoleManager.AddUserToRole("user-1", "role-1")
	s.True(added, "role wasn't added to user")
	added = s.userRoleManager.AddUserToRole("user-1", "role-1")
	s.False(added, "role wasn't re-added to user")
	s.userRoleManager.AddUserToRole("user-1", "role-2")
	roles := s.userRoleManager.GetRolesForUser("user-1")
	s.Equal(roles, []roles.Role{"role-1", "role-2"})
}

func (s *UserRoleManagementSuite) TestRemoveUser() {
	s.userRoleManager.AddUserToRole("user-1", "role-1")
	s.userRoleManager.AddUserToRole("user-1", "role-2")
	err := s.userRoleManager.RemoveUserFromRole("user-1", "role-1")
	s.NoError(err, "failure to remove role")
	err = s.userRoleManager.RemoveUserFromRole("user-1", "role-3")
	s.Error(err, "no error when removing a not existing role")
	roles := s.userRoleManager.GetRolesForUser("user-1")
	s.Equal(roles, []roles.Role{"role-2"})

}
