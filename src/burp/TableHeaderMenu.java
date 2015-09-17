package burp;

import java.awt.Color;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.Iterator;

import javax.swing.JCheckBox;
import javax.swing.JCheckBoxMenuItem;
import javax.swing.JComponent;
import javax.swing.JMenu;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import javax.swing.JPopupMenu;
import javax.swing.MenuSelectionManager;
import javax.swing.UIManager;
import javax.swing.plaf.ComponentUI;
import javax.swing.plaf.basic.BasicCheckBoxMenuItemUI;

import burp.BurpExtender.TableHelper;


public class TableHeaderMenu extends JPopupMenu{

	private final TableStructure columnObj;
	private final int	ITEM_PLAIN	=	0;	// Item types
	private final int	ITEM_CHECK	=	1;
	private final int	ITEM_RADIO	=	2;
	private final TableHelper tableHelper;

	public TableHeaderMenu(TableStructure columnObj, TableHelper tableHelper)
	{
		super();
		this.columnObj=columnObj;
		this.tableHelper = tableHelper;

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
							columnObj.getRegExData().setRegExString(newValue);
							saveAndReloadTableSettings(); //TODO do we need it?
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
				columnObj.setVisibleName(newValue);
				saveAndReloadTableSettings();
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
						if(MoreHelp.askConfirmMessage("Disabling a column", "Are you sure you want to disable the \""+ columnObj.getVisibleName()+"\"? This column may not be populated when it is disabled (if it needs additional resources)", msgOptions)==JOptionPane.YES_OPTION){
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
				for (Iterator<TableStructure> iterator = tableHelper.getTableHeaderColumnsDetails().getAllColumnsDefinitionList().iterator(); iterator.hasNext(); ) {
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
				for (Iterator<TableStructure> iterator = tableHelper.getTableHeaderColumnsDetails().getAllColumnsDefinitionList().iterator(); iterator.hasNext(); ) {
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
		
		for (Iterator<TableStructure> iterator = tableHelper.getTableHeaderColumnsDetails().getAllColumnsDefinitionList().iterator(); iterator.hasNext(); ) {
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
		tableHelper.saveTableChanges();
		tableHelper.getTableHeaderColumnsDetails().resetToCurrentVariables();
		tableHelper.getLogTableModel().fireTableStructureChanged();
		tableHelper.generatingTableColumns();
	}



}


