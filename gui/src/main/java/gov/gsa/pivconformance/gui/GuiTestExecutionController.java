package gov.gsa.pivconformance.gui;

import static org.junit.platform.engine.discovery.DiscoverySelectors.selectMethod;

import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.swing.JDialog;
import javax.swing.JOptionPane;
import javax.swing.JProgressBar;
import javax.swing.SwingUtilities;

import gov.gsa.pivconformance.cardlib.card.client.CachingDefaultPIVApplication;
import gov.gsa.pivconformance.cardlib.card.client.DataModelSingleton;
import gov.gsa.pivconformance.conformancelib.configuration.TestStatus;
import org.junit.platform.engine.DiscoverySelector;
import org.junit.platform.launcher.Launcher;
import org.junit.platform.launcher.LauncherDiscoveryRequest;
import org.junit.platform.launcher.TestExecutionListener;
import org.junit.platform.launcher.core.LauncherDiscoveryRequestBuilder;
import org.junit.platform.launcher.core.LauncherFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import ch.qos.logback.classic.LoggerContext;
import gov.gsa.pivconformance.conformancelib.configuration.CardSettingsSingleton;
import gov.gsa.pivconformance.conformancelib.configuration.ConformanceTestDatabase;
import gov.gsa.pivconformance.conformancelib.configuration.ParameterProviderSingleton;
import gov.gsa.pivconformance.conformancelib.configuration.TestCaseModel;
import gov.gsa.pivconformance.conformancelib.utilities.TestRunLogController;
import gov.gsa.pivconformance.conformancelib.configuration.TestStepModel;
import gov.gsa.pivconformance.cardlib.utils.PCSCWrapper;

public final class GuiTestExecutionController {
    private static final Logger s_logger = LoggerFactory.getLogger(GuiTestExecutionController.class);
    private static final GuiTestExecutionController INSTANCE = new GuiTestExecutionController();
    private static final String tag30TestId = "8.2.2.1"; // TODO: Fixme

    private TestRunLogController m_testRunLogController;
    private GuiTestTreePanel m_testTreePanel;
    private SimpleTestExecutionPanel m_testExecutionPanel;
    private GuiRunnerToolbar m_toolBar;
    private boolean m_running;
    private LoggerContext m_loggerContext;

    public static GuiTestExecutionController getInstance() {
        return INSTANCE;
    }

    private GuiTestExecutionController() {
        reset();
    }

    private void reset() {
        m_testTreePanel = null;
        m_testExecutionPanel = null;
        m_running = false;
        m_toolBar = null;
        m_testRunLogController = TestRunLogController.getInstance();
        m_testRunLogController.initialize();
    }

    public GuiTestTreePanel getTestTreePanel() {
        return m_testTreePanel;
    }

    public void setTestTreePanel(GuiTestTreePanel testTreePanel) {
        m_testTreePanel = testTreePanel;
    }

    public SimpleTestExecutionPanel getTestExecutionPanel() {
        return m_testExecutionPanel;
    }

    public void setTestExecutionPanel(SimpleTestExecutionPanel testExecutionPanel) {
        m_testExecutionPanel = testExecutionPanel;
    }

    public void setTestRunLogController(TestRunLogController logController) {
        m_testRunLogController = logController;
    }

    public TestRunLogController getTestRunLogController() {
        return m_testRunLogController;
    }

    public void setToolBar(GuiRunnerToolbar toolBar) {
        m_toolBar = toolBar;
    }

    public GuiRunnerToolbar getToolBar() {
        return m_toolBar;
    }

    public boolean isRunning() {
        return m_running;
    }

    public LoggerContext getLoggerContext() {
        return m_loggerContext;
    }

    public void setLoggerContext(LoggerContext loggerContext) {
        m_loggerContext = loggerContext;
    }

    void runAllTests(GuiTestCaseTreeNode root) {

        m_testRunLogController.setStartTimes();

        GuiDisplayTestReportAction display = GuiRunnerAppController.getInstance().getDisplayTestReportAction();
        display.setEnabled(false);

        s_logger.debug("----------------------------------------");
        s_logger.debug("FIPS 201 CCT " + GuiRunnerAppController.getInstance().getCctVersion());
        s_logger.debug("----------------------------------------");

        ConformanceTestDatabase db = GuiRunnerAppController.getInstance().getTestDatabase();
        if (db == null || db.getConnection() == null) {
            s_logger.error("Unable to run tests without a valid database");
            // XXX *** Display message don't just log it
            return;
        }
        m_running = true;
        GuiRunnerAppController.getInstance().reloadTree();
        PCSCWrapper pcsc = PCSCWrapper.getInstance();
        DataModelSingleton.getInstance().reset();

        int atomCount = 0;
        JProgressBar progress = m_testExecutionPanel.getTestProgressBar();
        try {
            SwingUtilities.invokeAndWait(() -> {
                m_testExecutionPanel.getRunButton().setEnabled(false);
                // TODO: Fix this or else
                m_toolBar.getComponents()[0].setEnabled(false);
                progress.setMaximum(db.getTestCaseCount());
                progress.setValue(0);
                progress.setVisible(true);
                progress.setStringPainted(true);
                progress.setString("");
            });
        } catch (InvocationTargetException | InterruptedException e1) {
            s_logger.error("Unable to launch tests", e1);
            m_running = false;
            return;
        }

        GuiTestListener guiListener = new GuiTestListener();
        guiListener.setProgressBar(progress);

        /*
         * Workaround to ensure that the tool is primed with the CHUID cert. TODO: Create "factory" database with
         * 8.2.2.1 as the only test, open, run, then open actual database.
         */

        int passes = 0;

        do {
            GuiTestCaseTreeNode curr = (GuiTestCaseTreeNode) root.getFirstChild();

            while (curr != null) {
                TestCaseModel testCase = curr.getTestCase();
                boolean runTest = false;
                String id = testCase.getIdentifier();
                if (passes % 2 == 1) { // TODO: Fixme
                    runTest = true;
                } else if (id.compareTo(GuiTestExecutionController.tag30TestId) == 0) {
                    m_testRunLogController.captureIdentifiers();
                    runTest = true;
                }
                if (testCase.getTestStatus().equals(TestStatus.TESTCATEGORY)) {
                    // Test categories don't need to be processed
                    runTest = false;
                }
                if (runTest) {
                    List<DiscoverySelector> discoverySelectors = new ArrayList<>();
                    List<TestStepModel> steps = testCase.getSteps();
                    for (TestStepModel currentStep : steps) {
                        atomCount++;
                        String testStepClassName = currentStep.getTestClassName();
                        String testStepMethodName = currentStep.getTestMethodName();
                        List<String> parameters = currentStep.getParameters();
                        Class<?> testClass = null;
                        try {
                            testClass = Class.forName(testStepClassName);
                        } catch (ClassNotFoundException e) {
                            s_logger.error("Class {} was configured in the database but the class could not be found.",
                                    testStepClassName);
                            break;
                        }

                        var matchingMethods = Stream.of(testClass.getMethods())
                                .filter(m -> m.getName().equals(testStepMethodName));

                        if (matchingMethods.count() != 1) {
                            s_logger.error(
                                    "Method {} was configured in the database but the method could not be found in class {}.",
                                    testStepClassName, testStepClassName);
                            break;
                        }

                        // Since we know there's one, we can just get it.
                        var testClassMethod = matchingMethods.collect(Collectors.toList()).get(0);

                        // Get all of the parameter types separated by commas
                        var testClassMethodParamsTypes = Stream.of(testClassMethod.getParameterTypes())
                                .map(t -> t.getName()).collect(Collectors.joining(", "));

                        // Create fullyQualifiedMethodName from components - formate ClassName#methodName(Param1,
                        // Param2, ...)
                        String fullyQualifiedMethodName = String.format("%s#%s(%s)",
                                testClass.getName() + testClassMethod.getName(), testClassMethodParamsTypes);

                        if (fullyQualifiedMethodName == testStepClassName) {
                            String errorMessage = "Test " + testCase.getIdentifier() + " specifies a test atom "
                                    + testStepClassName + "#" + testStepMethodName + "()"
                                    + " but no such method could be found for the class " + testStepClassName + "."
                                    + " (Test atom: " + currentStep.getTestDescription() + ")"
                                    + " Check that the database matches the included set of test atoms.";

                            s_logger.error(errorMessage);

                            if (passes % 2 == 1) { // TODO: Fixme
                                try {
                                    SwingUtilities.invokeAndWait(() -> {
                                        JOptionPane msgBox = new JOptionPane(errorMessage, JOptionPane.ERROR_MESSAGE);
                                        JDialog dialog = msgBox.createDialog(
                                                GuiRunnerAppController.getInstance().getMainFrame(), "Error");
                                        dialog.setAlwaysOnTop(true);
                                        dialog.setVisible(true);
                                    });
                                } catch (InvocationTargetException | InterruptedException e) {
                                    s_logger.error("Unable to display error dialog.");
                                }
                            }
                            break;
                        } // End skipped test

                        if (testStepClassName != null && !testStepClassName.isEmpty() && testClass != null) {
                            s_logger.trace("Adding {} from config", fullyQualifiedMethodName);
                            discoverySelectors.add(selectMethod(fullyQualifiedMethodName));
                            ParameterProviderSingleton.getInstance().addNamedParameter(fullyQualifiedMethodName,
                                    parameters);
                            String containerName = testCase.getContainer();
                            if (containerName != null && !containerName.isEmpty()) {
                                ParameterProviderSingleton.getInstance().addContainer(fullyQualifiedMethodName,
                                        containerName);
                            }
                            s_logger.trace("Added {} from config: {}", fullyQualifiedMethodName, parameters);
                        }

                    }
                    LauncherDiscoveryRequest launcherDiscoveryRequest = LauncherDiscoveryRequestBuilder.request()
                            .selectors(discoverySelectors)
                            .configurationParameter("TestCaseIdentifier", testCase.getIdentifier()).build();
                    Launcher launcher = LauncherFactory.create();
                    guiListener.setTestCaseIdentifier(testCase.getIdentifier());
                    guiListener.setTestCaseDescription(testCase.getDescription());
                    guiListener.setTestCaseExpectedResult(testCase.getExpectedStatus() == 1);
                    List<TestExecutionListener> listeners = new ArrayList<TestExecutionListener>();
                    listeners.add(guiListener);
                    registerListeners(launcher, listeners);

                    launcher.execute(launcherDiscoveryRequest);
                }
                curr = (GuiTestCaseTreeNode) curr.getNextSibling();
            }
        } while (++passes < 2); // End of CHUID priming workaround

        try

        {
            SwingUtilities.invokeAndWait(() -> {
                m_testExecutionPanel.getRunButton().setEnabled(true);
                // TODO: Fix this or else
                m_toolBar.getComponents()[0].setEnabled(true);
            });
        } catch (InvocationTargetException | InterruptedException e) {
            s_logger.error("Failed to enable run button", e);
        }

        s_logger.debug("Atom count: {}", atomCount);
        s_logger.debug("Tree count: {}", root.getChildCount() + root.getLeafCount());
        s_logger.debug("PCSC counters - connect() was called {} times, transmit() was called {} times",
                pcsc.getConnectCount(), pcsc.getTransmitCount());

        m_testRunLogController.setTimeStamps(); // Sets the timestamp for all of the logger files
        m_testRunLogController.cleanup();
        m_running = false;
        CardSettingsSingleton css = CardSettingsSingleton.getInstance();
        CachingDefaultPIVApplication cpiv = (CachingDefaultPIVApplication) css.getPivHandle();
        cpiv.clearCache();
        display.setEnabled(true);
    }

    private void registerListeners(Launcher l, List<TestExecutionListener> listeners) {
        for (TestExecutionListener listener : listeners) {
            l.registerTestExecutionListeners(listener);
        }
    }

    void runOneTest(GuiTestCaseTreeNode testCase) {

    }

    void runSelectedTests(List<GuiTestCaseTreeNode> testCases) {

    }
}
