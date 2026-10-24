package convert

import "database/sql"

func ToNullString(s string) sql.NullString {
	return sql.NullString{
		String: s,
		Valid:  s != "",
	}
}

func BoolToNullInt64(b bool, valid bool) sql.NullInt64 {
	var val int64
	if b {
		val = 1
	}
	return sql.NullInt64{
		Int64: val,
		Valid: valid,
	}
}
