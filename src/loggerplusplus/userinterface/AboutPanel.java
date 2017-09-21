//
// Burp Suite Logger++
// 
// Released as open source by NCC Group Plc - https://www.nccgroup.trust/
// 
// Developed by Soroush Dalili (@irsdl)
//
// Project link: http://www.github.com/nccgroup/BurpSuiteLoggerPlusPlus
//
// Released under AGPL see LICENSE for more information
//

package loggerplusplus.userinterface;

import loggerplusplus.LoggerPlusPlus;
import loggerplusplus.LoggerPreferences;
import loggerplusplus.MoreHelp;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;

public class AboutPanel extends JPanel {

	private final burp.IBurpExtenderCallbacks callbacks;
	private final LoggerPreferences loggerPreferences;
	/**
	 * Create the panel.
	 */
	public AboutPanel() {
		this.callbacks = LoggerPlusPlus.getCallbacks();
		this.loggerPreferences = LoggerPlusPlus.getInstance().getLoggerPreferences();
		this.setLayout(new BorderLayout());
		JPanel msgpane = new JPanel();
		ScrollablePanel scrollablePanel = new ScrollablePanel();
		scrollablePanel.setScrollableWidth( ScrollablePanel.ScrollableSizeHint.FIT );
		scrollablePanel.setLayout(new BorderLayout());
		scrollablePanel.add(msgpane);

		GridBagLayout gridBagLayout = new GridBagLayout();
		gridBagLayout.columnWidths = new int[]{0, 86, 80, 248, 0};
		gridBagLayout.rowHeights = new int[]{0, 38, 0, 0, 0, 43, 0, 0, 0, 0};
		gridBagLayout.columnWeights = new double[]{0.0, 0.0, 0.0, 0.0, Double.MIN_VALUE};
		gridBagLayout.rowWeights = new double[]{0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, Double.MIN_VALUE};
		msgpane.setLayout(gridBagLayout);

		ClassLoader cldr = this.getClass().getClassLoader();
		java.net.URL imageURLMain   = cldr.getResource("resources/AboutMain.png");
		JLabel lblMain = new JLabel("Main"); // to see the label in eclipse design tab!
		ImageIcon imageIconMain;
		if(imageURLMain != null) {
			imageIconMain = new ImageIcon(imageURLMain);
			if ("running".equals("running")) // to see the image while running it.
				lblMain = new JLabel(imageIconMain);
		}
		GridBagConstraints gbc_lblMain = new GridBagConstraints();
		gbc_lblMain.gridheight = 8;
		gbc_lblMain.insets = new Insets(0, 0, 0, 5);
		gbc_lblMain.gridx = 1;
		gbc_lblMain.gridy = 1;
		msgpane.add(lblMain, gbc_lblMain);

		JLabel lblName = new JLabel("Name");
		GridBagConstraints gbc_lblName = new GridBagConstraints();
		gbc_lblName.anchor = GridBagConstraints.SOUTHWEST;
		gbc_lblName.insets = new Insets(0, 0, 5, 5);
		gbc_lblName.gridx = 2;
		gbc_lblName.gridy = 1;
		msgpane.add(lblName, gbc_lblName);

		JLabel lblDynamicname = new JLabel("dynamic_name");
		GridBagConstraints gbc_lblDynamicname = new GridBagConstraints();
		gbc_lblDynamicname.anchor = GridBagConstraints.SOUTHWEST;
		gbc_lblDynamicname.insets = new Insets(0, 0, 5, 0);
		gbc_lblDynamicname.gridx = 3;
		gbc_lblDynamicname.gridy = 1;
		msgpane.add(lblDynamicname, gbc_lblDynamicname);

		JLabel lblVersion = new JLabel("Version");
		GridBagConstraints gbc_lblVersion = new GridBagConstraints();
		gbc_lblVersion.insets = new Insets(0, 0, 5, 5);
		gbc_lblVersion.anchor = GridBagConstraints.NORTHWEST;
		gbc_lblVersion.gridx = 2;
		gbc_lblVersion.gridy = 2;
		msgpane.add(lblVersion, gbc_lblVersion);

		JLabel lblDynamicversion = new JLabel("dynamic_version");
		GridBagConstraints gbc_lblDynamicversion = new GridBagConstraints();
		gbc_lblDynamicversion.anchor = GridBagConstraints.NORTHWEST;
		gbc_lblDynamicversion.insets = new Insets(0, 0, 5, 0);
		gbc_lblDynamicversion.gridx = 3;
		gbc_lblDynamicversion.gridy = 2;
		msgpane.add(lblDynamicversion, gbc_lblDynamicversion);

		JLabel lblSource = new JLabel("Source");
		GridBagConstraints gbc_lblSource = new GridBagConstraints();
		gbc_lblSource.anchor = GridBagConstraints.NORTHWEST;
		gbc_lblSource.insets = new Insets(0, 0, 5, 5);
		gbc_lblSource.gridx = 2;
		gbc_lblSource.gridy = 3;
		msgpane.add(lblSource, gbc_lblSource);

		JLabel lblDynamicsource = new JLabel("dynamic_source");
		GridBagConstraints gbc_lblDynamicsource = new GridBagConstraints();
		gbc_lblDynamicsource.anchor = GridBagConstraints.NORTHWEST;
		gbc_lblDynamicsource.insets = new Insets(0, 0, 5, 0);
		gbc_lblDynamicsource.gridx = 3;
		gbc_lblDynamicsource.gridy = 3;
		msgpane.add(lblDynamicsource, gbc_lblDynamicsource);

		JLabel lblAuthor = new JLabel("Author");
		GridBagConstraints gbc_lblAuthor = new GridBagConstraints();
		gbc_lblAuthor.anchor = GridBagConstraints.NORTHWEST;
		gbc_lblAuthor.insets = new Insets(0, 0, 5, 5);
		gbc_lblAuthor.gridx = 2;
		gbc_lblAuthor.gridy = 4;
		msgpane.add(lblAuthor, gbc_lblAuthor);

		JLabel lblDynamicauthor = new JLabel("dynamic_author");
		GridBagConstraints gbc_lblDynamicauthor = new GridBagConstraints();
		gbc_lblDynamicauthor.insets = new Insets(0, 0, 5, 0);
		gbc_lblDynamicauthor.anchor = GridBagConstraints.NORTHWEST;
		gbc_lblDynamicauthor.gridx = 3;
		gbc_lblDynamicauthor.gridy = 4;
		msgpane.add(lblDynamicauthor, gbc_lblDynamicauthor);

		JLabel label = new JLabel("          ");
		GridBagConstraints gbc_label = new GridBagConstraints();
		gbc_label.insets = new Insets(0, 0, 5, 5);
		gbc_label.gridx = 2;
		gbc_label.gridy = 5;
		msgpane.add(label, gbc_label);

		JButton btnOpenExtensionHome = new JButton("Open extension homepage");
		btnOpenExtensionHome.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				openWebpage(loggerPreferences.getProjectLink());
			}
		});
		GridBagConstraints gbc_btnOpenExtensionHome = new GridBagConstraints();
		gbc_btnOpenExtensionHome.insets = new Insets(0, 0, 5, 0);
		gbc_btnOpenExtensionHome.gridwidth = 2;
		gbc_btnOpenExtensionHome.anchor = GridBagConstraints.NORTHWEST;
		gbc_btnOpenExtensionHome.gridx = 2;
		gbc_btnOpenExtensionHome.gridy = 6;
		msgpane.add(btnOpenExtensionHome, gbc_btnOpenExtensionHome);

		JButton btnSubmitFilterIdea = new JButton("Submit a filter idea!");
		btnSubmitFilterIdea.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				openWebpage("http://twitter.com/home?status=%40CoreyD97%20L%2B%2B%20Filter%20Idea%3A%20");
			}
		});

		GridBagConstraints gbc_btnSubmitFilterIdea = new GridBagConstraints();
		gbc_btnSubmitFilterIdea.insets = new Insets(0, 0, 5, 0);
		gbc_btnSubmitFilterIdea.anchor = GridBagConstraints.WEST;
		gbc_btnSubmitFilterIdea.gridwidth = 2;
		gbc_btnSubmitFilterIdea.gridx = 2;
		gbc_btnSubmitFilterIdea.gridy = 7;
		msgpane.add(btnSubmitFilterIdea, gbc_btnSubmitFilterIdea);

		JButton btnReportAnIssue = new JButton("Report a bug/feature!");
		btnReportAnIssue.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				openWebpage(loggerPreferences.getProjectIssueLink());
			}
		});
		GridBagConstraints gbc_btnReportAnIssue = new GridBagConstraints();
		gbc_btnReportAnIssue.insets = new Insets(0, 0, 5, 0);
		gbc_btnReportAnIssue.anchor = GridBagConstraints.WEST;
		gbc_btnReportAnIssue.gridwidth = 2;
		gbc_btnReportAnIssue.gridx = 2;
		gbc_btnReportAnIssue.gridy = 8;
		msgpane.add(btnReportAnIssue, gbc_btnReportAnIssue);

		JButton btnCheckForUpdate = new JButton("Check for update");
		btnCheckForUpdate.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				new Thread(new Runnable()
				{
					@Override
					public void run()
					{
						MoreHelp.checkForUpdate(true);
					}
				}).start();
			}
		});
		GridBagConstraints gbc_btnCheckForUpdate = new GridBagConstraints();
		gbc_btnCheckForUpdate.anchor = GridBagConstraints.NORTHWEST;
		gbc_btnCheckForUpdate.gridwidth = 2;
		gbc_btnCheckForUpdate.gridx = 2;
		gbc_btnCheckForUpdate.gridy = 9;
		msgpane.add(btnCheckForUpdate, gbc_btnCheckForUpdate);
		
		lblDynamicname.setText(loggerPreferences.getAppName());
		lblDynamicversion.setText(String.valueOf(loggerPreferences.getVersion()));
		lblDynamicsource.setText(loggerPreferences.getProjectLink());
		lblDynamicauthor.setText(loggerPreferences.getAuthor());

		this.add(new JScrollPane(scrollablePanel), BorderLayout.CENTER);
	}

	private static void openWebpage(URI uri) {
		Desktop desktop = Desktop.isDesktopSupported() ? Desktop.getDesktop() : null;
		if (desktop != null && desktop.isSupported(Desktop.Action.BROWSE)) {
			try {
				desktop.browse(uri);
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
	}

	private static void openWebpage(String url) {
		try {
			openWebpage((new URL(url)).toURI());
		} catch (URISyntaxException e) {
			e.printStackTrace();
		} catch (MalformedURLException e) {
			e.printStackTrace();
		}
	}

}
