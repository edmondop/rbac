package decision_test

import (
	"github.com/edmondop/rbac/internal/decision"
	"github.com/edmondop/rbac/internal/policy"
	"github.com/edmondop/rbac/internal/roles"
	"github.com/stretchr/testify/suite"
	"testing"
)

type DecisionEngineTestSuite struct {
	suite.Suite
	engine *decision.DecisionEngine
	roles  map[roles.User][]roles.Role
}

func (suite *DecisionEngineTestSuite) GetRolesForUser(user roles.User) []roles.Role {
	return suite.roles[user]
}

func (suite *DecisionEngineTestSuite) GetAssignedPolicies(role roles.Role) []policy.Policy {
	switch {
	case role == "admin":
		return []policy.Policy{manageUserPolicy, manageProjectsPolicy, deploymentAdministratorPolicy}
	case role == "manager":
		return []policy.Policy{manageUserPolicy, manageProjectsPolicy}
	case role == "developer":
		return []policy.Policy{deploymentAdministratorPolicy}
	case role == "blacklisted":
		return []policy.Policy{noManageUserPolicy}
	}
	return []policy.Policy{}
}

var manageUserPolicy = policy.Policy{
	PolicyStatements: []policy.PolicyStatement{
		{
			StatementId: "ManageUsers",
			Actions:     []string{"AddUser", "RemoveUser"},
			Resources:   []string{"auto-kitteh://organizations/organization-1", "auto-kitteh://organization/organization-2"},
			Effect:      policy.Allow,
		},
	},
}

var noManageUserPolicy = policy.Policy{
	PolicyStatements: []policy.PolicyStatement{
		{
			StatementId: "ManageUsers",
			Actions:     []string{"AddUser", "RemoveUser"},
			Resources:   []string{"auto-kitteh://organizations/organization-1", "auto-kitteh://organization/organization-2"},
			Effect:      policy.Deny,
		},
	},
}

var manageProjectsPolicy = policy.Policy{
	PolicyStatements: []policy.PolicyStatement{
		{
			StatementId: "ManageProjects",
			Actions:     []string{"AddProject", "RemoveProject"},
			Resources:   []string{"auto-kitteh://organizations/organization-4", "auto-kitteh://organization/organization-5"},
			Effect:      policy.Allow,
		},
	},
}

var deploymentAdministratorPolicy = policy.Policy{
	PolicyStatements: []policy.PolicyStatement{
		{
			StatementId: "DeployProject",
			Actions:     []string{"DeployProject"},
			Resources:   []string{"auto-kitteh://organizations/organization-4/project-1"},
			Effect:      policy.Allow,
		},
		{
			StatementId: "ModifyEnvironment",
			Actions:     []string{"ModifyEnvironment"},
			Resources:   []string{"auto-kitteh://organizations/organization-4/project-1"},
			Effect:      policy.Allow,
		},
	},
}

func (suite *DecisionEngineTestSuite) SetupTest() {
	suite.roles = make(map[roles.User][]roles.Role)
	engine := decision.NewDecisionEngine(suite, suite)
	suite.engine = &engine
}

func TestDecisionEngine(t *testing.T) {
	suite.Run(t, new(DecisionEngineTestSuite))
}

func (suite *DecisionEngineTestSuite) TestDenyByDefault() {
	request := decision.Request{
		User:     "hello",
		Resource: "dummy",
		Action:   "dummy2",
	}
	suite.Assert().False(suite.engine.IsAuthorized(request), "request with no relevant policy wasn't denied")
}

func (suite *DecisionEngineTestSuite) TestDenyOverwriteAllow() {
	resource := "auto-kitteh://organizations/organization-1"
	action := "AddUser"
	user := roles.User("itay")
	suite.roles[user] = []roles.Role{"manager"}
	request := decision.Request{
		User:     user,
		Resource: resource,
		Action:   action,
	}
	suite.Assert().True(suite.engine.IsAuthorized(request), "request denied even if policies allow")
	suite.roles[user] = []roles.Role{"manager", "blacklisted"}
	suite.Assert().False(suite.engine.IsAuthorized(request), "request allowed even if a deny is present")
}

func (suite *DecisionEngineTestSuite) TestSimpleAllow() {
	resource := "auto-kitteh://organizations/organization-4/project-1"
	action := "DeployProject"
	user := roles.User("haim")
	suite.roles[user] = []roles.Role{"developer"}
	request := decision.Request{
		User:     user,
		Resource: resource,
		Action:   action,
	}
	suite.Assert().True(suite.engine.IsAuthorized(request), "request denied even if policies allow")
}

func (suite *DecisionEngineTestSuite) TestSimpleDeny() {
	resource := "auto-kitteh://organizations/organization-4/project-2"
	action := "DeployProject"
	user := roles.User("haim")
	suite.roles[user] = []roles.Role{"developer"}
	request := decision.Request{
		User:     user,
		Resource: resource,
		Action:   action,
	}
	suite.Assert().False(suite.engine.IsAuthorized(request), "request allowed even if policies denies it")
}
