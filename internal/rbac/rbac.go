package rbac

type User string

type Request struct {
	User     User
	Resource string
	Action   string
}
