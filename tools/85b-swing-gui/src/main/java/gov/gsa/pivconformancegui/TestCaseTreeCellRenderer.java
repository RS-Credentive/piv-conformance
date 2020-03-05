package gov.gsa.pivconformancegui;

import java.awt.Component;
import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;

import javax.swing.ImageIcon;
import javax.swing.JTree;
import javax.swing.tree.DefaultTreeCellRenderer;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import gov.gsa.conformancelib.configuration.TestCaseModel;
import gov.gsa.conformancelib.configuration.TestStatus;
import gov.gsa.conformancelib.configuration.TestStepModel;

public class TestCaseTreeCellRenderer extends DefaultTreeCellRenderer implements MouseListener {
	
	private static final long serialVersionUID = -7279235468508117069L;
    private static final Logger s_logger = LoggerFactory.getLogger(TestCaseTreeCellRenderer.class);
    
    private static Map<TestStatus, ImageIcon> s_statusIcons;
    
    static {
    	s_statusIcons = new HashMap<TestStatus, ImageIcon>();
    	for(TestStatus s : TestStatus.values()) {
    		switch(s) {
				case SKIP:
				{
					ImageIcon icon = getStatusIcon("error_go");
					s_statusIcons.put(s, icon);
					break;
				}
				case FAIL:
				{
					ImageIcon icon = getStatusIcon("cross");
					s_statusIcons.put(s, icon);
					break;
				}
				case PASS:
				{
					ImageIcon icon = getStatusIcon("accept");
					s_statusIcons.put(s, icon);
					break;
				}
				default:
				{
					ImageIcon icon = getStatusIcon("page");
					s_statusIcons.put(s, icon);
					break;
				}
    		}
    	}
    }
    
    // page = none
	// accept = pass
	// cross = fail
	// error_go = skip

	@Override
	public Component getTreeCellRendererComponent(JTree tree, Object value, boolean sel, boolean expanded, boolean leaf,
			int row, boolean hasFocus) {
		super.getTreeCellRendererComponent(tree, value, sel, expanded, leaf, row, hasFocus);
		TestStatus status = TestStatus.NONE;
		String description = "";
		if(value instanceof TestCaseTreeNode) {
			TestCaseTreeNode node = (TestCaseTreeNode)value;
			TestCaseModel test = node.getTestCase();
			if(test != null) {
				status = test.getTestStatus();
				description = test.getDescription();
			}
		} else if(value instanceof TestStepTreeNode) {
			TestStepTreeNode node = (TestStepTreeNode)value;
			TestStepModel step = node.getTestStep();
			if(step != null) {
				status = step.getTestStatus();
				description = step.toString();
			}
		}
		ImageIcon icon = s_statusIcons.get(status);
		if(icon != null) {
			if (description.length() != 0) {
				icon.setDescription(description);
			}
			setIcon(icon);
			//s_logger.info("Got {} for {}", icon.getDescription(), status);
		} else {
			s_logger.error("icon was null for tree node");
		}
		return this;
	}

	public TestCaseTreeCellRenderer() {
	}
	
	protected static ImageIcon getStatusIcon(String imageName) {
		String imgLocation = "/icons/" + imageName + ".png";
		URL imageUrl = GuiRunnerAppController.class.getResource(imgLocation);
		if(imageUrl == null) {
			s_logger.error("Unable to get image at classpath location {}", imgLocation);
			return null;
		}
		return new ImageIcon(imageUrl, imgLocation);
	}

	@Override
	public void mouseClicked(MouseEvent e) {
		s_logger.debug("Mouse clicked");
	}

	@Override
	public void mousePressed(MouseEvent e) {
		s_logger.debug("Mouse pressed");
	}

	@Override
	public void mouseReleased(MouseEvent e) {
		s_logger.debug("Mouse released");
	}

	@Override
	public void mouseEntered(MouseEvent e) {
		s_logger.debug("Mouse entered");
	}

	@Override
	public void mouseExited(MouseEvent e) {
		s_logger.debug("Mouse exited");
	}

}
