package burp;

import javax.swing.JFileChooser;
import javax.swing.JOptionPane;
import javax.swing.JPanel;

import java.awt.Component;
import java.awt.Desktop;
import java.awt.GridBagLayout;

import javax.swing.JButton;
import javax.swing.filechooser.FileNameExtensionFilter;

import java.awt.GridBagConstraints;
import java.io.*;
import java.net.*;
import java.util.List;
import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;

import javax.swing.JLabel;

import java.awt.Insets;

import javax.swing.JCheckBox;
import javax.swing.JToggleButton;

import java.awt.Font;

import javax.swing.event.ChangeListener;
import javax.swing.event.ChangeEvent;

import burp.BurpExtender.LogEntry;
import burp.BurpExtender.LogTableModel;



public class LoggerOptionsPanel extends JPanel {


	private final burp.IBurpExtenderCallbacks callbacks;
	private final PrintWriter stdout;
	private final PrintWriter stderr;
	private boolean canSaveCSV;
	private JFileChooser chooser;
	private File csvFile;
	private boolean cancelOp = false;
	private final LoggerPreferences loggerPreferences;
	
	private JToggleButton tglbtnIsEnabled = new JToggleButton("Logger++ Is Running");
	private JToggleButton tglbtnRedirectResults = new JToggleButton("Redirection to Output Tab Is Enabled");
	private JCheckBox chckbxIsRestrictedToScope = new JCheckBox("In scope items only");
	private JCheckBox chckbxAllTools = new JCheckBox("All Tools");
	private JCheckBox chckbxSpider = new JCheckBox("Spider");
	private JCheckBox chckbxIntruder = new JCheckBox("Intruder");
	private JCheckBox chckbxScanner = new JCheckBox("Scanner");
	private JCheckBox chckbxRepeater = new JCheckBox("Repeater");
	private JCheckBox chckbxSequencer = new JCheckBox("Sequencer");
	private JCheckBox chckbxProxy = new JCheckBox("Proxy");
	private JButton btnSaveLogsButton = new JButton("Save Table Logs as CSV");
	private JButton btnSaveFullLogs = new JButton("Save Full Logs as CSV (slow)");
	private final JLabel lblAddonLabel = new JLabel("");
	private final JCheckBox chckbxExtender = new JCheckBox("Extender");
	private final JCheckBox chckbxTarget = new JCheckBox("Target");
	private final JLabel lblNewLabel = new JLabel("Note 1: Extensive logging  may affect Burp Suite performance.");
	private final JLabel lblNoteIn = new JLabel("Note 2: In order to save the data automatically, use Options > Misc > Logging");
	private final JLabel label = new JLabel("                ");

	/**
	 * Create the panel.
	 * @param stderr 
	 * @param stdout 
	 * @param log 
	 * @param canSaveCSV 
	 * @param loggerPreferences 
	 * @param logTable 
	 * @param logTable 
	 */
	public LoggerOptionsPanel(final IBurpExtenderCallbacks callbacks, final PrintWriter stdout, final PrintWriter stderr, final LogTableModel logTableModel, final List<LogEntry> log, boolean canSaveCSV, final LoggerPreferences loggerPreferences) {
		this.callbacks = callbacks;
		this.stdout = stdout;
		this.stderr = stderr;
		this.canSaveCSV = canSaveCSV;
		this.loggerPreferences = loggerPreferences;
		
		GridBagLayout gridBagLayout = new GridBagLayout();
		gridBagLayout.columnWidths = new int[]{0, 94, 320, 250, 0, 0};
		gridBagLayout.rowHeights = new int[]{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
		gridBagLayout.columnWeights = new double[]{0.0, 0.0, 0.0, 0.0, 0.0, Double.MIN_VALUE};
		gridBagLayout.rowWeights = new double[]{0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, Double.MIN_VALUE};
		setLayout(gridBagLayout);

		GridBagConstraints gbc_label = new GridBagConstraints();
		gbc_label.insets = new Insets(0, 0, 5, 5);
		gbc_label.gridx = 0;
		gbc_label.gridy = 1;
		add(label, gbc_label);

		JLabel lblLoggerStatus = new JLabel("Status:");
		lblLoggerStatus.setFont(new Font("Tahoma", Font.BOLD, 14));
		GridBagConstraints gbc_lblLoggerStatus = new GridBagConstraints();
		gbc_lblLoggerStatus.anchor = GridBagConstraints.WEST;
		gbc_lblLoggerStatus.fill = GridBagConstraints.VERTICAL;
		gbc_lblLoggerStatus.insets = new Insets(0, 0, 5, 5);
		gbc_lblLoggerStatus.gridx = 1;
		gbc_lblLoggerStatus.gridy = 1;
		add(lblLoggerStatus, gbc_lblLoggerStatus);


		//		JToggleButton tglbtnNewToggleButton = new JToggleButton("Logger++ Is Running");
		tglbtnIsEnabled.setFont(new Font("Tahoma", Font.PLAIN, 13));
		GridBagConstraints gbc_tglbtnIsEnabled = new GridBagConstraints();
		gbc_tglbtnIsEnabled.fill = GridBagConstraints.BOTH;
		gbc_tglbtnIsEnabled.insets = new Insets(0, 0, 5, 5);
		gbc_tglbtnIsEnabled.gridx = 2;
		gbc_tglbtnIsEnabled.gridy = 1;
		add(tglbtnIsEnabled, gbc_tglbtnIsEnabled);

		JButton btnClearTheLog = new JButton("Clear The Logs Table");
		btnClearTheLog.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				//BurpExtender.logTableReset();
				boolean origState = loggerPreferences.isEnabled();
				loggerPreferences.setEnabled(false);

				log.clear();

				logTableModel.fireTableDataChanged();
				loggerPreferences.setEnabled(origState);	
				setPreferencesValues();
			}
		});
		btnClearTheLog.setFont(new Font("Tahoma", Font.PLAIN, 13));
		GridBagConstraints gbc_btnClearTheLog = new GridBagConstraints();
		gbc_btnClearTheLog.fill = GridBagConstraints.HORIZONTAL;
		gbc_btnClearTheLog.insets = new Insets(0, 0, 5, 5);
		gbc_btnClearTheLog.gridx = 3;
		gbc_btnClearTheLog.gridy = 1;
		add(btnClearTheLog, gbc_btnClearTheLog);

		JLabel lblOnlyCaptureIn = new JLabel("");
		GridBagConstraints gbc_lblOnlyCaptureIn = new GridBagConstraints();
		gbc_lblOnlyCaptureIn.insets = new Insets(0, 0, 5, 5);
		gbc_lblOnlyCaptureIn.gridx = 2;
		gbc_lblOnlyCaptureIn.gridy = 2;
		add(lblOnlyCaptureIn, gbc_lblOnlyCaptureIn);

		JLabel lblScopes = new JLabel("Scope:");
		lblScopes.setFont(new Font("Tahoma", Font.BOLD, 14));
		GridBagConstraints gbc_lblScopes = new GridBagConstraints();
		gbc_lblScopes.anchor = GridBagConstraints.WEST;
		gbc_lblScopes.insets = new Insets(0, 0, 5, 5);
		gbc_lblScopes.gridx = 1;
		gbc_lblScopes.gridy = 3;
		add(lblScopes, gbc_lblScopes);

		//		JCheckBox chckbxNewCheckBox = new JCheckBox("In scope items only");
		GridBagConstraints gbc_chckbxIsRestrictedToScope = new GridBagConstraints();
		gbc_chckbxIsRestrictedToScope.anchor = GridBagConstraints.WEST;
		gbc_chckbxIsRestrictedToScope.insets = new Insets(0, 0, 5, 5);
		gbc_chckbxIsRestrictedToScope.gridx = 2;
		gbc_chckbxIsRestrictedToScope.gridy = 3;
		add(chckbxIsRestrictedToScope, gbc_chckbxIsRestrictedToScope);

		
		btnSaveLogsButton.setToolTipText("This does not save requests and responses");
		btnSaveLogsButton.setFont(new Font("Tahoma", Font.PLAIN, 13));
		btnSaveLogsButton.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				try {
					chooser = null;
					obtainFileName("logger++_table");
					if(csvFile!=null){
						ExcelExporter exp = new ExcelExporter(); 
						exp.exportTable(log, csvFile, false); 	
					}

				} catch (IOException ex) {
					stderr.println(ex.getMessage());
					ex.printStackTrace();

				}
			}
		});
		GridBagConstraints gbc_btnSaveLogsButton = new GridBagConstraints();
		gbc_btnSaveLogsButton.fill = GridBagConstraints.HORIZONTAL;
		gbc_btnSaveLogsButton.insets = new Insets(0, 0, 5, 5);
		gbc_btnSaveLogsButton.gridx = 3;
		gbc_btnSaveLogsButton.gridy = 3;
		add(btnSaveLogsButton, gbc_btnSaveLogsButton);

		JLabel lblLogFrom = new JLabel("Log From:");
		lblLogFrom.setFont(new Font("Tahoma", Font.BOLD, 14));
		GridBagConstraints gbc_lblLogFrom = new GridBagConstraints();
		gbc_lblLogFrom.anchor = GridBagConstraints.WEST;
		gbc_lblLogFrom.insets = new Insets(0, 0, 5, 5);
		gbc_lblLogFrom.gridx = 1;
		gbc_lblLogFrom.gridy = 4;
		add(lblLogFrom, gbc_lblLogFrom);

		GridBagConstraints gbc_btnSaveFullLogs = new GridBagConstraints();
		gbc_btnSaveFullLogs.fill = GridBagConstraints.HORIZONTAL;
		gbc_btnSaveFullLogs.insets = new Insets(0, 0, 5, 5);
		gbc_btnSaveFullLogs.gridx = 3;
		gbc_btnSaveFullLogs.gridy = 4;
		btnSaveFullLogs.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				try {
					chooser = null;
					obtainFileName("logger++_full");
					if(csvFile!=null){
						ExcelExporter exp = new ExcelExporter(); 
						exp.exportTable(log, csvFile, true); 	
					}

				} catch (IOException ex) {
					stderr.println(ex.getMessage());
					ex.printStackTrace();

				}
			}


		});
		btnSaveFullLogs.setToolTipText("This can be slow and  messy when response is more than 32760 characters - not recommended!");
		btnSaveFullLogs.setFont(new Font("Tahoma", Font.PLAIN, 13));
		add(btnSaveFullLogs, gbc_btnSaveFullLogs);

		//		JCheckBox chckbxNewCheckBox_1 = new JCheckBox("All Tools");
		GridBagConstraints gbc_chckbxAllTools = new GridBagConstraints();
		gbc_chckbxAllTools.anchor = GridBagConstraints.WEST;
		gbc_chckbxAllTools.insets = new Insets(0, 0, 5, 5);
		gbc_chckbxAllTools.gridx = 2;
		gbc_chckbxAllTools.gridy = 5;
		add(chckbxAllTools, gbc_chckbxAllTools);

		//		JCheckBox chckbxSpider = new JCheckBox("Spider");
		GridBagConstraints gbc_chckbxSpider = new GridBagConstraints();
		gbc_chckbxSpider.anchor = GridBagConstraints.WEST;
		gbc_chckbxSpider.insets = new Insets(0, 0, 5, 5);
		gbc_chckbxSpider.gridx = 2;
		gbc_chckbxSpider.gridy = 6;
		add(chckbxSpider, gbc_chckbxSpider);

		//		JCheckBox chckbxIntruder = new JCheckBox("Intruder");
		GridBagConstraints gbc_chckbxIntruder = new GridBagConstraints();
		gbc_chckbxIntruder.anchor = GridBagConstraints.WEST;
		gbc_chckbxIntruder.insets = new Insets(0, 0, 5, 5);
		gbc_chckbxIntruder.gridx = 2;
		gbc_chckbxIntruder.gridy = 7;
		add(chckbxIntruder, gbc_chckbxIntruder);

		//		JCheckBox chckbxScanner = new JCheckBox("Scanner");
		GridBagConstraints gbc_chckbxScanner = new GridBagConstraints();
		gbc_chckbxScanner.anchor = GridBagConstraints.WEST;
		gbc_chckbxScanner.insets = new Insets(0, 0, 5, 5);
		gbc_chckbxScanner.gridx = 2;
		gbc_chckbxScanner.gridy = 8;
		add(chckbxScanner, gbc_chckbxScanner);

		//		JCheckBox chckbxRepeater = new JCheckBox("Repeater");
		GridBagConstraints gbc_chckbxRepeater = new GridBagConstraints();
		gbc_chckbxRepeater.anchor = GridBagConstraints.WEST;
		gbc_chckbxRepeater.insets = new Insets(0, 0, 5, 5);
		gbc_chckbxRepeater.gridx = 2;
		gbc_chckbxRepeater.gridy = 9;
		add(chckbxRepeater, gbc_chckbxRepeater);

		//		JCheckBox chckbxSequencer = new JCheckBox("Sequencer");
		GridBagConstraints gbc_chckbxSequencer = new GridBagConstraints();
		gbc_chckbxSequencer.anchor = GridBagConstraints.WEST;
		gbc_chckbxSequencer.insets = new Insets(0, 0, 5, 5);
		gbc_chckbxSequencer.gridx = 2;
		gbc_chckbxSequencer.gridy = 10;
		add(chckbxSequencer, gbc_chckbxSequencer);

		//		JCheckBox chckbxProxy = new JCheckBox("Proxy");
		GridBagConstraints gbc_chckbxProxy = new GridBagConstraints();
		gbc_chckbxProxy.anchor = GridBagConstraints.WEST;
		gbc_chckbxProxy.insets = new Insets(0, 0, 5, 5);
		gbc_chckbxProxy.gridx = 2;
		gbc_chckbxProxy.gridy = 11;
		add(chckbxProxy, gbc_chckbxProxy);

		GridBagConstraints gbc_chckbxTarget = new GridBagConstraints();
		gbc_chckbxTarget.anchor = GridBagConstraints.WEST;
		gbc_chckbxTarget.insets = new Insets(0, 0, 5, 5);
		gbc_chckbxTarget.gridx = 2;
		gbc_chckbxTarget.gridy = 12;
		add(chckbxTarget, gbc_chckbxTarget);

		GridBagConstraints gbc_chckbxExtender = new GridBagConstraints();
		gbc_chckbxExtender.anchor = GridBagConstraints.WEST;
		gbc_chckbxExtender.insets = new Insets(0, 0, 5, 5);
		gbc_chckbxExtender.gridx = 2;
		gbc_chckbxExtender.gridy = 13;
		add(chckbxExtender, gbc_chckbxExtender);


		JLabel labelEmpty_1 = new JLabel("    ");	
		GridBagConstraints gbc_labelEmpty_1 = new GridBagConstraints();
		gbc_labelEmpty_1.insets = new Insets(0, 0, 5, 5);
		gbc_labelEmpty_1.gridx = 1;
		gbc_labelEmpty_1.gridy = 14;
		add(labelEmpty_1, gbc_labelEmpty_1);


		JButton btnOpenExtensionHome = new JButton("Open Extension Home Page");
		GridBagConstraints gbc_btnOpenExtensionHome = new GridBagConstraints();
		gbc_btnOpenExtensionHome.fill = GridBagConstraints.HORIZONTAL;
		gbc_btnOpenExtensionHome.insets = new Insets(0, 0, 5, 5);
		gbc_btnOpenExtensionHome.gridx = 3;
		gbc_btnOpenExtensionHome.gridy = 14;
		btnOpenExtensionHome.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				openWebpage(loggerPreferences.getProjectLink());
			}
		});

		JButton btnResetSettings = new JButton("Reset Settings");
		btnResetSettings.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				loggerPreferences.resetLoggerPreferences();
				setPreferencesValues();
			}

		});
		btnResetSettings.setFont(new Font("Tahoma", Font.PLAIN, 13));
		GridBagConstraints gbc_btnResetSettings = new GridBagConstraints();
		gbc_btnResetSettings.fill = GridBagConstraints.HORIZONTAL;
		gbc_btnResetSettings.insets = new Insets(0, 0, 5, 5);
		gbc_btnResetSettings.gridx = 2;
		gbc_btnResetSettings.gridy = 14;
		add(btnResetSettings, gbc_btnResetSettings);
		add(btnOpenExtensionHome, gbc_btnOpenExtensionHome);

		GridBagConstraints gbc_lblAddonLabel = new GridBagConstraints();
		gbc_lblAddonLabel.anchor = GridBagConstraints.WEST;
		gbc_lblAddonLabel.gridwidth = 3;
		gbc_lblAddonLabel.insets = new Insets(0, 0, 5, 5);
		gbc_lblAddonLabel.gridx = 1;
		gbc_lblAddonLabel.gridy = 15;
		add(lblAddonLabel, gbc_lblAddonLabel);

		GridBagConstraints gbc_lblNewLabel = new GridBagConstraints();
		gbc_lblNewLabel.anchor = GridBagConstraints.WEST;
		gbc_lblNewLabel.gridwidth = 3;
		gbc_lblNewLabel.insets = new Insets(0, 0, 5, 5);
		gbc_lblNewLabel.gridx = 1;
		gbc_lblNewLabel.gridy = 16;
		add(lblNewLabel, gbc_lblNewLabel);

		GridBagConstraints gbc_lblNoteIn = new GridBagConstraints();
		gbc_lblNoteIn.anchor = GridBagConstraints.WEST;
		gbc_lblNoteIn.gridwidth = 3;
		gbc_lblNoteIn.insets = new Insets(0, 0, 5, 5);
		gbc_lblNoteIn.gridx = 1;
		gbc_lblNoteIn.gridy = 17;
		add(lblNoteIn, gbc_lblNoteIn);
		tglbtnRedirectResults.setEnabled(false);
		tglbtnRedirectResults.setToolTipText("Only exprimental... Use Options > Misc > Logging to log the data");


		//		JToggleButton tglbtnRedirectResultsTo = new JToggleButton("Redirection to Output Tab Is Enabled");
		tglbtnRedirectResults.setFont(new Font("Tahoma", Font.PLAIN, 13));
		GridBagConstraints gbc_tglbtnRedirectResults = new GridBagConstraints();
		gbc_tglbtnRedirectResults.fill = GridBagConstraints.HORIZONTAL;
		gbc_tglbtnRedirectResults.insets = new Insets(0, 0, 0, 5);
		gbc_tglbtnRedirectResults.gridx = 3;
		gbc_tglbtnRedirectResults.gridy = 18;
		add(tglbtnRedirectResults, gbc_tglbtnRedirectResults);

		setPreferencesValues();
		setComponentsActions();
	}

	// source: http://book.javanb.com/swing-hacks/swinghacks-chp-3-sect-6.html
	public class ExcelExporter {
		public ExcelExporter() { }
		public void exportTable(List<LogEntry> log, File file, boolean isFullLog) throws IOException {

			FileWriter out = new FileWriter(file);

			boolean firstRun = true;

			for(LogEntry item:log){
				if(firstRun){
					out.write(item.getCSVHeader(isFullLog));

					out.write("\n");
					firstRun = false;
				}
				out.write(item.toCSVString(isFullLog));

				out.write("\n");
			}

			out.close();
			stdout.println("write out to: " + file);
		}

	}


	// source: https://community.oracle.com/thread/1357495?start=0&tstart=0
	private void obtainFileName(String filename) {
		cancelOp = false;
		csvFile = null;
		FileNameExtensionFilter filter = new FileNameExtensionFilter("Excel Format (CSV)", "csv");
		if(chooser == null) {
			chooser = new JFileChooser();
			chooser.setDialogTitle("Saving Database");
			chooser.setFileFilter(filter);
			chooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
			chooser.setSelectedFile( new File(filename+".csv") );
			chooser.setAcceptAllFileFilterUsed(false);                      
		}

		int val = chooser.showSaveDialog((Component)null);

		if(val == JFileChooser.APPROVE_OPTION) {
			csvFile = chooser.getSelectedFile();
			boolean fixed = fixExtension(csvFile, "csv");

			if(!fixed && !cancelOp) {
				JOptionPane.showMessageDialog(null,"File Name Specified Not Supported",
						"File Name Error", JOptionPane.ERROR_MESSAGE);
				obtainFileName(filename);
				return;
			}

		}
		if (cancelOp){
			csvFile = null;
		}
	}

	private boolean fixExtension(File file, String prefExt) {
		String fileName = file.getName();
		String dir = file.getParentFile().getAbsolutePath();

		String ext = null;

		try {
			ext = fileName.substring( fileName.lastIndexOf("."), fileName.length() );
			stdout.println("Original File Extension: " + ext);
		} catch(StringIndexOutOfBoundsException e) {
			ext = null;
		}

		if(ext != null && !ext.equalsIgnoreCase("."+prefExt)) {
			return false;
		}

		String csvName = null;

		if(ext == null || ext.length() == 0) {
			csvName = fileName + "." + prefExt;
		} else {
			csvName = fileName.substring(0, fileName.lastIndexOf(".") + 1) + prefExt;
		}

		stdout.println("Corrected File Name: " + csvName);

		File csvCert = new File(dir, csvName);

		if(csvCert.exists()) {
			int val = JOptionPane.showConfirmDialog(null, "Replace Existing File?", "File Exists",
					JOptionPane.YES_NO_CANCEL_OPTION, JOptionPane.WARNING_MESSAGE);

			if(val == JOptionPane.NO_OPTION) {
				obtainFileName(file.getName());
				cancelOp = true;
				return false;
			} else if(val == JOptionPane.CANCEL_OPTION) {
				cancelOp = true;
				return false;               
			}
		} 

		if(!file.renameTo(csvCert)) {
			file = new File(dir, csvName);
			try {
				file.createNewFile();
			} catch(IOException ioe) {}
		}

		stdout.println("Exporting as: " + file.getAbsolutePath() );

		return true;
	}



	private void setComponentsActions(){
		chckbxIsRestrictedToScope.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				loggerPreferences.setRestrictedToScope(chckbxIsRestrictedToScope.isSelected());
			}
		});

		chckbxAllTools.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				loggerPreferences.setEnabled4All(chckbxAllTools.isSelected());
			}
		});

		chckbxSpider.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				loggerPreferences.setEnabled4Spider(chckbxSpider.isSelected());
			}
		});

		chckbxIntruder.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				loggerPreferences.setEnabled4Intruder(chckbxIntruder.isSelected());
			}
		});

		chckbxScanner.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				loggerPreferences.setEnabled4Scanner(chckbxScanner.isSelected());
			}
		});

		chckbxRepeater.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				loggerPreferences.setEnabled4Repeater(chckbxRepeater.isSelected());
			}
		});

		chckbxSequencer.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				loggerPreferences.setEnabled4Sequencer(chckbxSequencer.isSelected());
			}
		});

		chckbxProxy.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				loggerPreferences.setEnabled4Proxy(chckbxProxy.isSelected());
			}
		});

		chckbxExtender.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				loggerPreferences.setEnabled4Extender(chckbxExtender.isSelected());
			}
		});

		chckbxTarget.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent arg0) {
				loggerPreferences.setEnabled4TargetTab(chckbxTarget.isSelected());
			}
		});

		tglbtnIsEnabled.addChangeListener(new ChangeListener() {
			public void stateChanged(ChangeEvent arg0) {
				toggleButtonAction(tglbtnIsEnabled,tglbtnIsEnabled.isSelected());
			}
		});

		tglbtnRedirectResults.addChangeListener(new ChangeListener() {
			public void stateChanged(ChangeEvent e) {
				toggleButtonAction(tglbtnRedirectResults,tglbtnRedirectResults.isSelected());
			}
		});

		tglbtnRedirectResults.setVisible(false);
	}

	private void toggleButtonAction(JToggleButton targetToggleBtn, boolean isSelected){
		if(targetToggleBtn==tglbtnIsEnabled){
			if(isSelected){
				tglbtnIsEnabled.setText("Logger++ Is Running");
			}else{	
				tglbtnIsEnabled.setText("Logger++ Is Stopped");
			}
			loggerPreferences.setEnabled(isSelected);
			tglbtnIsEnabled.setSelected(isSelected);
		}else if(targetToggleBtn==tglbtnRedirectResults){
			if(isSelected){
				tglbtnRedirectResults.setText("Redirection to Output Tab Is Enabled");
			}else{

				tglbtnRedirectResults.setText("Redirection to Output Tab Is Disabled");
			}
			loggerPreferences.setOutputRedirected(isSelected);
			tglbtnRedirectResults.setSelected(isSelected);
		}
	}


	private void setPreferencesValues(){

		chckbxIsRestrictedToScope.setSelected(loggerPreferences.isRestrictedToScope());
		chckbxAllTools.setSelected(loggerPreferences.isEnabled4All());
		chckbxSpider.setSelected(loggerPreferences.isEnabled4Spider());
		chckbxIntruder.setSelected(loggerPreferences.isEnabled4Intruder());
		chckbxScanner.setSelected(loggerPreferences.isEnabled4Scanner());
		chckbxRepeater.setSelected(loggerPreferences.isEnabled4Repeater());
		chckbxSequencer.setSelected(loggerPreferences.isEnabled4Sequencer());
		chckbxProxy.setSelected(loggerPreferences.isEnabled4Proxy());
		chckbxExtender.setSelected(loggerPreferences.isEnabled4Extender());
		chckbxTarget.setSelected(loggerPreferences.isEnabled4TargetTab());

		toggleButtonAction(tglbtnIsEnabled,loggerPreferences.isEnabled());
		toggleButtonAction(tglbtnRedirectResults,loggerPreferences.isOutputRedirected());

		lblAddonLabel.setText(loggerPreferences.getAppInfo());
		
		if(!canSaveCSV){
			btnSaveLogsButton.setEnabled(false);
			btnSaveFullLogs.setEnabled(false);
			btnSaveLogsButton.setToolTipText("Please look at the extension's error tab.");
			btnSaveFullLogs.setToolTipText("Please look at the extension's error tab.");
		}
	}

	public static void openWebpage(URI uri) {
		Desktop desktop = Desktop.isDesktopSupported() ? Desktop.getDesktop() : null;
		if (desktop != null && desktop.isSupported(Desktop.Action.BROWSE)) {
			try {
				desktop.browse(uri);
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
	}

	public static void openWebpage(String url) {
		try {
			openWebpage((new URL(url)).toURI());
		} catch (URISyntaxException e) {
			e.printStackTrace();
		} catch (MalformedURLException e) {
			e.printStackTrace();
		}
	}
}
