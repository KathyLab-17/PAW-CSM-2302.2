BeforeAll {
    . $PSCommandPath.Replace('.Tests.ps1', '.ps1')
}

Describe "ApplicationControl" {
    It "Returns expected output" {
        ApplicationControl | Should -Be "YOUR_EXPECTED_VALUE"
    }
}
