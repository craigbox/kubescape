package v2

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/kubescape/kubescape/v2/core/cautils"
	"github.com/kubescape/kubescape/v2/core/pkg/resultshandling/printer"
	"github.com/kubescape/opa-utils/reporthandling/results/v1/reportsummary"
	"github.com/owenrumney/go-sarif/v2/sarif"
)

const (
	sarifOutputFile = "report"
	sarifOutputExt  = ".sarif"

	toolName    = "kubescape"
	toolInfoURI = "https://armosec.io"
)

// SARIFPrinter is a printer that emits the report in the SARIF format
type SARIFPrinter struct {
	// outputFile is the name of the output file
	writer *os.File
}

// NewSARIFPrinter returns a new SARIF printer instance
func NewSARIFPrinter() *SARIFPrinter {
	return &SARIFPrinter{}
}

func (sp *SARIFPrinter) Score(score float32) {
	return
}

func (sp *SARIFPrinter) SetWriter(outputFile string) {
	if outputFile == "" {
		outputFile = sarifOutputFile
	}
	if filepath.Ext(strings.TrimSpace(outputFile)) != sarifOutputExt {
		outputFile = outputFile + sarifOutputExt
	}
	sp.writer = printer.GetWriter(outputFile)
}

func (sp *SARIFPrinter) ActionPrint(opaSessionObj *cautils.OPASessionObj) {
	report, err := sarif.New(sarif.Version210)
	if err != nil {
		panic(err)
	}

	run := sarif.NewRunWithInformationURI(toolName, toolInfoURI)

	for resourceID, result := range opaSessionObj.ResourcesResult {
		if result.GetStatus(nil).IsFailed() {
			resourceSource := opaSessionObj.ResourceSource[resourceID]
			filepath := resourceSource.RelativePath

			for _, ac := range result.AssociatedControls {
				if ac.GetStatus(nil).IsFailed() {
					ctl := opaSessionObj.Report.SummaryDetails.Controls.GetControl(reportsummary.EControlCriteriaID, ac.GetID())

					run.AddRule(ctl.GetID()).
						WithShortDescription(sarif.NewMultiformatMessageString(ctl.GetDescription())).
						WithFullDescription(sarif.NewMultiformatMessageString(ctl.GetDescription())).
						WithHelp(sarif.NewMultiformatMessageString(ctl.GetRemediation()))

					run.CreateResultForRule(ac.GetName()).
						WithMessage(sarif.NewTextMessage(ctl.GetDescription())).
						AddLocation(
							sarif.NewLocationWithPhysicalLocation(
								sarif.NewPhysicalLocation().
									WithArtifactLocation(
										sarif.NewSimpleArtifactLocation(filepath),
									).WithRegion(
									sarif.NewSimpleRegion(0, 1),
								),
							),
						)
				}
			}
		}
	}

	report.AddRun(run)

	report.PrettyWrite(sp.writer)
}
