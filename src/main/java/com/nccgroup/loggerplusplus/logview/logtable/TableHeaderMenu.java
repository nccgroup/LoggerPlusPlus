package com.nccgroup.loggerplusplus.logview.logtable;

import com.nccgroup.loggerplusplus.logentry.FieldGroup;
import com.nccgroup.loggerplusplus.util.MoreHelp;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseEvent;
import java.util.*;


public class TableHeaderMenu extends JPopupMenu{

	private final LogTableController logTableController;
	private final LogTable logTable;
	private final LogTableColumn columnObj;

	public TableHeaderMenu(LogTableController logTableController, LogTableColumn columnObj)
	{
		this.logTableController = logTableController;
		this.logTable = logTableController.getLogTable();
		this.columnObj=columnObj;

	}

	public void showMenu(MouseEvent e){

		JPopupMenu menu = new JPopupMenu("Popup");
		JMenuItem item = new JMenuItem(columnObj.getVisibleName() + " (" + columnObj.getIdentifier().getFullLabel() + ")");

		item.setEnabled(false);
		menu.add(item);
		menu.addSeparator();

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
					logTableController.getLogTableColumnModel().saveLayout();
				}
			}
		});
		menu.add(item);

		item = new JMenuItem("Hide");
		item.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				logTable.getColumnModel().toggleHidden(columnObj);
			}
		});
		menu.add(item);

		JMenu subMenuVisibleCols = new JMenu("Visible columns");
		item = new JMenuItem("Make all visible");
		item.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				for (LogTableColumn column : logTable.getColumnModel().getAllColumns()) {
					logTable.getColumnModel().showColumn(column);
				}
				logTableController.getLogTableColumnModel().saveLayout();
			}
		});
		subMenuVisibleCols.add(item);

		Map<FieldGroup, JMenu> groupMenus = new HashMap<>();

		for (LogTableColumn logTableColumn : logTable.getColumnModel().getAllColumns()) {

			FieldGroup group = logTableColumn.getIdentifier().getFieldGroup();
			if (!groupMenus.containsKey(group)) {
				groupMenus.put(group, new JMenu(group.getLabel()));
			}
			JMenu fieldGroupMenu = groupMenus.get(group);

			JMenuItem visibleItem = new JCheckBoxMenuItem(logTableColumn.getVisibleName());
			visibleItem.setSelected(logTableColumn.isVisible());
			visibleItem.addActionListener(e1 -> logTable.getColumnModel().toggleHidden(logTableColumn));
			fieldGroupMenu.add(visibleItem);
		}

		List<FieldGroup> fieldGroups = new ArrayList<FieldGroup>(groupMenus.keySet());
		fieldGroups.sort(Enum::compareTo);

		for (FieldGroup fieldGroup : fieldGroups) {
			subMenuVisibleCols.add(groupMenus.get(fieldGroup));
		}

		menu.add(subMenuVisibleCols);

		menu.show(e.getComponent(), e.getX(), e.getY());
	}



}


