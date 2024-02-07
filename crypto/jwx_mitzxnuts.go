package crypto

func GetSupportedAlgorithms() []string {
	var algorithms []string
	for _, curr := range supportedAlgorithms {
		algorithms = append(algorithms, curr.String())
	}

	return algorithms
}
