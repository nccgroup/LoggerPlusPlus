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
		gridBagLayout.columnWidths = new int[]{0, 1, 1, 0};
		gridBagLayout.rowHeights = new int[]{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
		gridBagLayout.columnWeights = new double[]{0.0, 1.0, 1.0, 0.0, Double.MIN_VALUE};
		gridBagLayout.rowWeights = new double[]{0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, Double.MIN_VALUE};
		msgpane.setLayout(gridBagLayout);

		ClassLoader cldr = this.getClass().getClassLoader();
		URL imageURLMain = cldr.getResource("resources/AboutMain.png");
		JLabel lblMain = new JLabel("NCC LOGO"); // to see the label in eclipse design tab!
		ImageIcon imageIconMain;
		if(imageURLMain != null) {
			imageIconMain = new ImageIcon(imageURLMain);
			lblMain = new JLabel(imageIconMain);
		}
		GridBagConstraints gbc = new GridBagConstraints();
		gbc.anchor = GridBagConstraints.NORTHWEST;
		gbc.fill = GridBagConstraints.NONE;
		gbc.weightx = gbc.weighty = 0;
		gbc.gridheight = 9;
		gbc.insets = new Insets(0, 0, 0, 15);
		gbc.gridx = 0;
		gbc.gridy = 0;
		msgpane.add(lblMain, gbc);

		gbc.weightx = 1;
		gbc.anchor = GridBagConstraints.NORTHWEST;

		JLabel lblName = new JLabel("Name");
		gbc.insets = new Insets(15, 0, 5, 5);
		gbc.gridheight = 1;
		gbc.gridx++;
		msgpane.add(lblName, gbc);

		JLabel lblDynamicname = new JLabel("dynamic_name");
		gbc.insets = new Insets(15, 0, 5, 0);
		gbc.gridx = 2;
		msgpane.add(lblDynamicname, gbc);

		JLabel lblVersion = new JLabel("Version");
		gbc.insets = new Insets(0, 0, 5, 5);
		gbc.gridx = 1;
		gbc.gridy++;
		msgpane.add(lblVersion, gbc);

		JLabel lblDynamicversion = new JLabel("dynamic_version");
		gbc.insets = new Insets(0, 0, 5, 0);
		gbc.gridx++;
		msgpane.add(lblDynamicversion, gbc);

		JLabel lblSource = new JLabel("Source");
		gbc.insets = new Insets(0, 0, 5, 5);
		gbc.gridx = 1;
		gbc.gridy++;
		msgpane.add(lblSource, gbc);

		JLabel lblDynamicsource = new JLabel("dynamic_source");
		gbc.insets = new Insets(0, 0, 5, 0);
		gbc.gridx++;
		msgpane.add(lblDynamicsource, gbc);

		JLabel lblAuthor = new JLabel("Author");
		gbc.insets = new Insets(0, 0, 5, 5);
		gbc.gridx = 1;
		gbc.gridy++;
		msgpane.add(lblAuthor, gbc);

		JLabel lblDynamicauthor = new JLabel("dynamic_author");
		gbc.insets = new Insets(0, 0, 20, 0);
		gbc.gridx++;
		msgpane.add(lblDynamicauthor, gbc);

		JButton btnOpenExtensionHome = new JButton("Open extension homepage");
		btnOpenExtensionHome.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				openWebpage(loggerPreferences.getProjectLink());
			}
		});
		gbc.insets = new Insets(0, 0, 10, 0);
		gbc.gridwidth = 2;
		gbc.gridx = 1;
		gbc.gridy++;
		msgpane.add(btnOpenExtensionHome, gbc);

		JButton btnSubmitFilterIdea = new JButton("Submit a filter idea!");
		btnSubmitFilterIdea.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				openWebpage("http://twitter.com/home?status=%40CoreyD97%20L%2B%2B%20Filter%20Idea%3A%20");
			}
		});
		gbc.gridy++;
		msgpane.add(btnSubmitFilterIdea, gbc);

		JButton btnReportAnIssue = new JButton("Report a bug/feature!");
		btnReportAnIssue.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				openWebpage(loggerPreferences.getProjectIssueLink());
			}
		});
		gbc.gridy++;
		msgpane.add(btnReportAnIssue, gbc);

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
		gbc.gridy++;
		msgpane.add(btnCheckForUpdate, gbc);

		gbc.gridx = 3;
		gbc.weightx = 100;
		msgpane.add(new JLabel(""), gbc);
		
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
