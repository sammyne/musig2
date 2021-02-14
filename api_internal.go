package musig2

var (
	commitmentLabel           = []byte("commitment")
	commitmentSignLabel       = []byte("sign:R")
	commitmentTranscriptLabel = []byte("MuSig-commitment")
	randWitnessLabel          = []byte("MuSigWitness")

	labelPKChoice = []byte("pk-choice")
	labelPKSet    = []byte("pk-set")
	labelR        = []byte("R")
	labelSignR    = []byte("sign:R")
)
