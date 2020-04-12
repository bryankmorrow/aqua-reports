package reports

type Reports interface {
	Get(w http.ResponseWriter, r *http.Request)
}

// RunningTime - Start the Report Timer
func RunningTime(r Reports) time.Time {
	return time.Now()
}

// Track - Stop the Report Timer
func Track(r Reports, startTime time.Time) time.Time {
	endTime := time.Now()
	return endTime.Sub(startTime)
}
