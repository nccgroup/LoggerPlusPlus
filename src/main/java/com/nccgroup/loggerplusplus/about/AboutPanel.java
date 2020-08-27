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

package com.nccgroup.loggerplusplus.about;

import com.coreyd97.BurpExtenderUtilities.Alignment;
import com.coreyd97.BurpExtenderUtilities.PanelBuilder;
import com.coreyd97.BurpExtenderUtilities.Preferences;
import com.nccgroup.loggerplusplus.util.Globals;
import com.nccgroup.loggerplusplus.util.userinterface.NoTextSelectionCaret;
import com.nccgroup.loggerplusplus.util.userinterface.WrappedTextPane;

import javax.swing.*;
import javax.swing.text.Style;
import javax.swing.text.StyleConstants;
import javax.swing.text.StyledDocument;
import java.awt.*;
import java.awt.event.ComponentAdapter;
import java.awt.event.ComponentEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.image.BufferedImage;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;

public class AboutPanel extends JPanel {

	private final Preferences preferences;
	private JComponent panel;

	public AboutPanel(Preferences preferences){
		this.setLayout(new BorderLayout());
		this.preferences = preferences;

		this.panel = buildMainPanel();
		this.add(panel, BorderLayout.NORTH);
		this.setMinimumSize(panel.getSize());
		this.addMouseListener(new MouseAdapter() {
			@Override
			public void mouseClicked(MouseEvent e) {
				if(e.getButton() == MouseEvent.BUTTON2){
					AboutPanel.this.removeAll();
					panel = buildMainPanel();
					AboutPanel.this.add(panel, BorderLayout.NORTH);
					AboutPanel.this.setMinimumSize(panel.getSize());
					AboutPanel.this.revalidate();
					AboutPanel.this.repaint();
				}
			}
		});
	}

	private JComponent buildMainPanel(){
		JLabel headerLabel = new JLabel("Logger++");
		Font font = this.getFont().deriveFont(32f).deriveFont(this.getFont().getStyle() | Font.BOLD);
		headerLabel.setFont(font);
		headerLabel.setHorizontalAlignment(SwingConstants.CENTER);


		JLabel subtitle = new JLabel("Advanced multithreaded logging tool");
		Font subtitleFont = subtitle.getFont().deriveFont(16f).deriveFont(subtitle.getFont().getStyle() | Font.ITALIC);
		subtitle.setFont(subtitleFont);
		subtitle.setHorizontalAlignment(SwingConstants.CENTER);

		JSeparator separator = new JSeparator(SwingConstants.HORIZONTAL);
		JPanel separatorPadding = new JPanel();
		separatorPadding.setBorder(BorderFactory.createEmptyBorder(0,0,7,0));

		BufferedImage twitterImage = loadImage("TwitterLogo.png");
		JButton twitterButton;
		if(twitterImage != null){
			twitterButton = new JButton("Follow me (@CoreyD97) on Twitter", new ImageIcon(scaleImageToWidth(twitterImage, 20)));
			twitterButton.setComponentOrientation(ComponentOrientation.RIGHT_TO_LEFT);
			twitterButton.setIconTextGap(7);
		}else{
			twitterButton = new JButton("Follow me (@CoreyD97) on Twitter");
		}

		twitterButton.setMaximumSize(new Dimension(0, 10));

		twitterButton.addActionListener(actionEvent -> {
			try {
				Desktop.getDesktop().browse(new URI(Globals.TWITTER_URL));
			} catch (IOException | URISyntaxException e) {}
		});

		JButton irsdlTwitterButton;
		if(twitterImage != null){
			irsdlTwitterButton = new JButton("Follow Soroush (@irsdl) on Twitter", new ImageIcon(scaleImageToWidth(twitterImage, 20)));
			irsdlTwitterButton.setComponentOrientation(ComponentOrientation.RIGHT_TO_LEFT);
			irsdlTwitterButton.setIconTextGap(7);
		}else{
			irsdlTwitterButton = new JButton("Follow Soroush (@irsdl) on Twitter");
		}

		irsdlTwitterButton.setMaximumSize(new Dimension(0, 10));

		irsdlTwitterButton.addActionListener(actionEvent -> {
			try {
				Desktop.getDesktop().browse(new URI(Globals.IRSDL_TWITTER_URL));
			} catch (IOException | URISyntaxException e) {}
		});


		JButton nccTwitterButton;
		BufferedImage nccImage = loadImage("NCCGroup.png");
		if(nccImage != null){
			nccTwitterButton = new JButton("Follow NCC Group on Twitter", new ImageIcon(scaleImageToWidth(nccImage, 20)));
			nccTwitterButton.setComponentOrientation(ComponentOrientation.RIGHT_TO_LEFT);
			nccTwitterButton.setIconTextGap(7);
		}else{
			nccTwitterButton = new JButton("Follow NCC Group on Twitter");
		}

		nccTwitterButton.addActionListener(actionEvent -> {
			try {
				Desktop.getDesktop().browse(new URI(Globals.NCC_TWITTER_URL));
			} catch (IOException | URISyntaxException e) {}
		});

		String githubLogoFilename = "GitHubLogo" +
				(UIManager.getLookAndFeel().getName().equalsIgnoreCase("darcula") ? "White" : "Black")
				+ ".png";
		BufferedImage githubImage = loadImage(githubLogoFilename);
//		JButton viewOnGithubButton;
		JButton submitFeatureRequestButton;
		JButton reportBugButton;
		if(githubImage != null){
//			viewOnGithubButton = new JButton("View Project on GitHub", new ImageIcon(scaleImageToWidth(githubImage, 20)));
//			viewOnGithubButton.setComponentOrientation(ComponentOrientation.RIGHT_TO_LEFT);
//			viewOnGithubButton.setIconTextGap(7);
			submitFeatureRequestButton = new JButton("Submit Feature Request", new ImageIcon(scaleImageToWidth(githubImage, 20)));
			submitFeatureRequestButton.setComponentOrientation(ComponentOrientation.RIGHT_TO_LEFT);
			submitFeatureRequestButton.setIconTextGap(7);
			reportBugButton = new JButton("Report an Issue", new ImageIcon(scaleImageToWidth(githubImage, 20)));
			reportBugButton.setComponentOrientation(ComponentOrientation.RIGHT_TO_LEFT);
			reportBugButton.setIconTextGap(7);
		}else{
//			viewOnGithubButton = new JButton("View Project on GitHub");
			submitFeatureRequestButton = new JButton("Submit Feature Request", new ImageIcon(scaleImageToWidth(githubImage, 20)));
			reportBugButton = new JButton("Report an Issue", new ImageIcon(scaleImageToWidth(githubImage, 20)));
		}
//		viewOnGithubButton.addActionListener(actionEvent -> {
//			try {
//				Desktop.getDesktop().browse(new URI(Globals.GITHUB_URL));
//			} catch (IOException | URISyntaxException e) {}
//		});

		submitFeatureRequestButton.addActionListener(actionEvent -> {
			try {
				Desktop.getDesktop().browse(new URI(Globals.GITHUB_FEATURE_URL));
			} catch (IOException | URISyntaxException e) {}
		});
		reportBugButton.addActionListener(actionEvent -> {
			try {
				Desktop.getDesktop().browse(new URI(Globals.GITHUB_BUG_URL));
			} catch (IOException | URISyntaxException e) {}
		});


		BufferedImage nccLargeImage = loadImage("NCCLarge.png");
		ImageIcon nccLargeImageIcon = new ImageIcon(scaleImageToWidth(nccLargeImage, 300));
		JLabel nccBranding = new JLabel(nccLargeImageIcon);
		nccBranding.addComponentListener(new ComponentAdapter() {
			@Override
			public void componentResized(ComponentEvent e) {
				int width = e.getComponent().getWidth();
				nccLargeImageIcon.setImage(scaleImageToWidth(nccLargeImage, width));
			}
		});

		JLabel createdBy = new JLabel("Developed by: Corey Arthur ( @CoreyD97 )");
		createdBy.setHorizontalAlignment(SwingConstants.CENTER);
		createdBy.setBorder(BorderFactory.createEmptyBorder(0,0,7,0));
		JLabel ideaBy = new JLabel("Originally by: Soroush Dalili ( @irsdl )");
		ideaBy.setHorizontalAlignment(SwingConstants.CENTER);
		ideaBy.setBorder(BorderFactory.createEmptyBorder(0,0,7,0));
		JLabel version = new JLabel("Version: " + Globals.VERSION);
		version.setBorder(BorderFactory.createEmptyBorder(0,0,7,0));
		version.setHorizontalAlignment(SwingConstants.CENTER);
		JComponent creditsPanel = PanelBuilder.build(new JComponent[][]{
					new JComponent[]{createdBy},
					new JComponent[]{ideaBy},
					new JComponent[]{version},
					new JComponent[]{nccBranding},
					new JComponent[]{nccBranding}
			}, Alignment.FILL, 1, 1);

		WrappedTextPane aboutContent = new WrappedTextPane();
		aboutContent.setLayout(new BorderLayout());
		aboutContent.setEditable(false);
		aboutContent.setOpaque(false);
		aboutContent.setCaret(new NoTextSelectionCaret(aboutContent));

		JScrollPane aboutScrollPane = new JScrollPane(aboutContent);
		aboutScrollPane.setBorder(null);
		aboutScrollPane.setHorizontalScrollBarPolicy(ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
		Style bold = aboutContent.getStyledDocument().addStyle("bold", null);
		StyleConstants.setBold(bold, true);
		Style italics = aboutContent.getStyledDocument().addStyle("italics", null);
		StyleConstants.setItalic(italics, true);


		try {
			String featuresTitle = "Features\n\n";
			String features = " \u2022 Log requests from all tools\n" +
					" \u2022 Define filters to search requests\n" +
					" \u2022 Create rules to highlight interesting requests\n" +
					" \u2022 Grep all entries for regex patterns and extract matching groups\n" +
					" \u2022 Import entries from WStalker, OWASP ZAP\n" +
					" \u2022 Export entries to elasticsearch, CSV\n" +
					" \u2022 Multithreaded\n\n" +
					"Want a feature implementing? Make a request using the buttons above!\n" +
					"Want to help improve Logger++? Submit a pull request!\n\n" +
					"Like the extension? Let me know by giving it a star on GitHub.\n\n";

			String thanksTo = "Thanks To:\n";
			String thanksText = "Shaddy, ours-code, jselvi, jaesbit, wotgl, StanHVA, theblackturtle, cnotin, latacora-tomekr";

			String[] sections = new String[]{featuresTitle, features, thanksTo, thanksText};
			Style[] styles = new Style[]{bold, null, null, italics};

			StyledDocument document = aboutContent.getStyledDocument();
			for (int i = 0; i < sections.length; i++) {
				String section = sections[i];
				document.insertString(document.getLength(), String.valueOf(section), styles[i]);
			}

		} catch (Exception e) {
			StringWriter writer = new StringWriter();
			e.printStackTrace(new PrintWriter(writer));
		}

		aboutContent.setBorder(BorderFactory.createEmptyBorder(10,10,10,10));
		JScrollPane aboutContentScrollPane = new JScrollPane(aboutContent);
		aboutContentScrollPane.setBorder(BorderFactory.createEmptyBorder(5, 0, 0, 0));

		JPanel panel = PanelBuilder.build(new JComponent[][]{
				new JComponent[]{headerLabel, headerLabel},
				new JComponent[]{subtitle, subtitle},
				new JComponent[]{separator, separator},
				new JComponent[]{separatorPadding, separatorPadding},
				new JComponent[]{creditsPanel, twitterButton},
				new JComponent[]{creditsPanel, irsdlTwitterButton},
				new JComponent[]{creditsPanel, nccTwitterButton},
				new JComponent[]{creditsPanel, submitFeatureRequestButton},
				new JComponent[]{creditsPanel, reportBugButton},
				new JComponent[]{aboutContentScrollPane, aboutContentScrollPane},
		}, new int[][]{
				new int[]{1,1},
				new int[]{1,1},
				new int[]{1,1},
				new int[]{1,1},
				new int[]{1,1},
				new int[]{1,1},
				new int[]{1,1},
				new int[]{1,1},
				new int[]{0,0},
		}, Alignment.TOPMIDDLE, 0.5, 0.9);
		return panel;
	}

	private BufferedImage loadImage(String filename){
		ClassLoader cldr = this.getClass().getClassLoader();
		URL imageURLMain = cldr.getResource(filename);

		if(imageURLMain != null) {
			Image original = new ImageIcon(imageURLMain).getImage();
			ImageIcon originalIcon = new ImageIcon(original);
			BufferedImage bufferedImage = new BufferedImage(originalIcon.getIconWidth(), originalIcon.getIconHeight(), BufferedImage.TYPE_INT_ARGB);
			Graphics2D g = (Graphics2D) bufferedImage.getGraphics();
			g.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
			g.drawImage(originalIcon.getImage(), null, null);
			return bufferedImage;
		}
		return null;
	}

	private Image scaleImageToWidth(BufferedImage image, int width){
		int height = (int) (Math.floor((image.getHeight() * width) / (double) image.getWidth()));
		return image.getScaledInstance(width, height, Image.SCALE_SMOOTH);
	}

}
