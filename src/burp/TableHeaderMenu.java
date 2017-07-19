package burp;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseEvent;
import java.io.PrintWriter;
import java.util.Iterator;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;


public class TableHeaderMenu extends JPopupMenu{

	private final Table table;
	private final TableStructure columnObj;
	private final int	ITEM_PLAIN	=	0;	// Item types
	private final int	ITEM_CHECK	=	1;
	private final int	ITEM_RADIO	=	2;
	private final PrintWriter stdout,stderr;
	private final boolean isDebug;

	public TableHeaderMenu(Table table, TableStructure columnObj, PrintWriter stdout, PrintWriter stderr, boolean isDebug)
	{
		super();
		this.table = table;
		this.columnObj=columnObj;
		this.stdout = stdout;
		this.stderr = stderr;
		this.isDebug = isDebug;

	}

	public void showMenu(MouseEvent e){
		boolean isRegex=columnObj.isRegEx();

		JPopupMenu menu = new JPopupMenu("Popup");
		JMenuItem item = new JMenuItem(columnObj.getVisibleName());

		item.setEnabled(false);
		menu.add(item);
		menu.addSeparator();

		if(isRegex){
			JMenu submenu = new JMenu("Regex");

			item = new JMenuItem("Edit");
			item.addActionListener(new ActionListener() {
				public void actionPerformed(ActionEvent e) {
					javax.swing.SwingUtilities.invokeLater(new Runnable() {
						public void run() {
							String newValue = MoreHelp.showPlainInputMessage("Regular expression for the \"" + columnObj.getVisibleName()+
									"\" column", "Edit Regex", columnObj.getRegExData().getRegExString());
							// Save it only if it is different! no need to refresh the columns
							if(!newValue.equals(columnObj.getRegExData().getRegExString())){
								// a mew RegEx string has been provided - we need to ensure that it is a valid regular expression to prevent confusion!
								try {
						            Pattern.compile(newValue);
						            columnObj.getRegExData().setRegExString(newValue);
									saveAndReloadTableSettings(); //TODO do we need it?
						        } catch (PatternSyntaxException exception) {
						            stderr.println("provided regular expression was wrong. It cannot be saved.");
						            MoreHelp.showWarningMessage("The provided regular expression string was NOT in correct format. It cannot be saved.");
						        }
							}
						}
					});
				}
			});

			submenu.add(item);		

			item = new JCheckBoxMenuItem("Case sensitive");
			item.setSelected(columnObj.getRegExData().isRegExCaseSensitive());
			item.addActionListener(new ActionListener() {
				public void actionPerformed(ActionEvent e) {
					columnObj.getRegExData().setRegExCaseSensitive(!columnObj.getRegExData().isRegExCaseSensitive());
				}
			});

			submenu.add(item);

			menu.add(submenu);


		}

		item = new JMenuItem("Rename");
		item.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				String newValue = MoreHelp.showPlainInputMessage("Rename the \"" + columnObj.getDefaultVisibleName()+
						"\" column", "Rename column name", columnObj.getVisibleName());
				if(newValue.isEmpty()){
					newValue = columnObj.getDefaultVisibleName();
				}
				// Save it only if it is different! no need to refresh the columns
				if(!newValue.equals(columnObj.getDefaultVisibleName())){
					columnObj.setVisibleName(newValue);
					saveAndReloadTableSettings();
				}
			}
		});
		menu.add(item);

		item = new JMenuItem("Hide");
		item.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				columnObj.setVisible(false);
				saveAndReloadTableSettings();
			}
		});
		menu.add(item);

		item = new JMenuItem("Disable");
		item.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {

				javax.swing.SwingUtilities.invokeLater(new Runnable() {
					public void run() {
						String[] msgOptions = { "OK", "CANCEL" };
						String message = "Are you sure you want to disable the \""+ columnObj.getVisibleName()
								+"\"? This column may not be populated when it is disabled (if it needs additional resources)";

						if(MoreHelp.askConfirmMessage("Disabling a column", message, msgOptions)==JOptionPane.YES_OPTION){
							columnObj.setEnabled(false);
							saveAndReloadTableSettings();
						}
					}
				});
			}
		});
		menu.add(item);

		JMenu subMenuVisibleCols = new JMenu("Visbile columns");
		item = new JMenuItem("Make all visible");
		item.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				for (Iterator<TableStructure> iterator = table.getModel().getTableHeaderColumnsDetails().getAllColumnsDefinitionList().iterator(); iterator.hasNext(); ) {
					final TableStructure columnDefinition = iterator.next();
					if(columnDefinition.isEnabled() && !columnDefinition.isVisible()){
						columnDefinition.setVisible(true);
					}
				}
				saveAndReloadTableSettings();
			}
		});
		subMenuVisibleCols.add(item);
		
		JMenu subMenuEnabledCols = new JMenu("Enabled columns");
		item = new JMenuItem("Make all enabled");
		item.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				for (Iterator<TableStructure> iterator = table.getModel().getTableHeaderColumnsDetails().getAllColumnsDefinitionList().iterator(); iterator.hasNext(); ) {
					final TableStructure columnDefinition = iterator.next();
					if(!columnDefinition.isEnabled()){
						columnDefinition.setEnabled(true);
						columnDefinition.setVisible(true);
					}
				}
				saveAndReloadTableSettings();
			}
		});
		subMenuEnabledCols.add(item);
		
		for (Iterator<TableStructure> iterator = table.getModel().getTableHeaderColumnsDetails().getAllColumnsDefinitionList().iterator(); iterator.hasNext(); ) {
			final TableStructure columnDefinition = iterator.next();

			if(columnDefinition.isEnabled()){
				JMenuItem visibleItem = new JCheckBoxMenuItem(columnDefinition.getVisibleName());
				visibleItem.setSelected(columnDefinition.isVisible());
				visibleItem.addActionListener(new ActionListener() {
					public void actionPerformed(ActionEvent e) {
						columnDefinition.setVisible(!columnDefinition.isVisible());
						saveAndReloadTableSettings();
					}
				});
				subMenuVisibleCols.add(visibleItem);
			}

			JMenuItem enabledItem = new JCheckBoxMenuItem(columnDefinition.getVisibleName());
			enabledItem.setSelected(columnDefinition.isEnabled());
			enabledItem.addActionListener(new ActionListener() {
				public void actionPerformed(ActionEvent e) {
					columnDefinition.setEnabled(!columnDefinition.isEnabled());
					columnDefinition.setVisible(true); // when a field is enabled, then it becomes visible automatically
					javax.swing.SwingUtilities.invokeLater(new Runnable() {
						public void run() {
							if(columnDefinition.isEnabled())
								MoreHelp.showMessage("The new field might not have been populated previously. It will be populated for the new messages.");
						}
					});
					saveAndReloadTableSettings();
				}
			});
			subMenuEnabledCols.add(enabledItem);
		}

		menu.add(subMenuVisibleCols);
		menu.add(subMenuEnabledCols);

		menu.show(e.getComponent(), e.getX(), e.getY());
	}

	public void saveAndReloadTableSettings(){
		//Stop automatically logging, prevents changing of csv format midway through
		//TODO constant csv format?
		if(table.getLoggerPreferences().getAutoSave()){
			MoreHelp.showMessage("The table structure has been changed. Autosave was disabled to prevent invalid csv.");
			table.getLoggerPreferences().setAutoSave(false);
		}
		table.saveTableChanges();
		table.getModel().getTableHeaderColumnsDetails().resetToCurrentVariables();
		table.getModel().fireTableStructureChanged();
		table.generatingTableColumns();
	}



}


