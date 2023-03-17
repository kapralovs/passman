package account

type AccountInfo struct {
	ID       int64  `json:"id,omitempty"`
	Name     string `json:"name,omitempty"`
	Login    string `json:"login,omitempty"`
	Password string `json:"password,omitempty"`
}
