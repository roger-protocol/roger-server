package convert

import "database/sql"

func ToNullString(s string) sql.NullString {
	return sql.NullString{
		String: s,
		Valid:  s != "",
	}
}

func FromNullString(s sql.NullString) *string {
	if s.Valid {
		return &s.String
	}
	return nil
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
