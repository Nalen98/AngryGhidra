package angryghidra;

import java.awt.Color;
import java.awt.GridBagConstraints;
import java.awt.Insets;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import docking.action.MenuData;
import docking.widgets.textfield.IntegerTextField;
import ghidra.app.context.ListingActionContext;
import ghidra.app.context.ListingContextAction;
import ghidra.app.plugin.core.colorizer.ColorizingService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;

public class AngryGhidraPopupMenu extends ListingContextAction {
    public final String MenuName = "AngryGhidraPlugin";
    public final String Group_Name = "SymEx";
    static Address CurrentFindAddr;
    static Address CurrentBlankAddr;
    static List < Address > CurrentAvoidAddrses;
    public static PluginTool tool;
    public static Program program;
    public AngryGhidraPopupMenu(AngryGhidraPlugin plugin, Program program) {
        super("AngryGhidraPlugin", plugin.getName());
        setProgram(program);
        tool = plugin.getTool();
        setupActions();
    }

    public void setProgram(Program p) {
        program = p;
    }

    public void setupActions() {

        tool.setMenuGroup(new String[] {
            MenuName
        }, Group_Name);             

        CurrentAvoidAddrses = new ArrayList < Address > ();
        ListingContextAction SetFind = new ListingContextAction("Set Find Address", getName()) {

            @Override
            protected void actionPerformed(ListingActionContext context) {

                if (CurrentFindAddr != null) {
                    UnSetColor(CurrentFindAddr);
                }
                Address address = context.getLocation().getAddress();
                CurrentFindAddr = address;
                SetColor(address, Color.GREEN);
                AngryGhidraProvider.TFFind.setText("0x" + address.toString());

            }
        };

        SetFind.setPopupMenuData(new MenuData(new String[] {
            MenuName,
            "Set",
            "Find Address"
        }, null, Group_Name));
        tool.addAction(SetFind);

        ListingContextAction UnSetFind = new ListingContextAction("Unset Find Address", getName()) {

            @Override
            protected void actionPerformed(ListingActionContext context) {

                Address address = context.getLocation().getAddress();
                UnSetColor(address);
                CurrentFindAddr = null;
               AngryGhidraProvider.TFFind.setText("");

            }
        };

        UnSetFind.setPopupMenuData(new MenuData(new String[] {
            MenuName,
            "Unset",
            "Find Address"
        }, null, Group_Name));
        tool.addAction(UnSetFind);

        ListingContextAction SetBlankState = new ListingContextAction("Set Blank State Address", getName()) {

            @Override
            protected void actionPerformed(ListingActionContext context) {

                if (CurrentBlankAddr != null) {
                    UnSetColor(CurrentBlankAddr);
                }
                Address address = context.getLocation().getAddress();
                CurrentBlankAddr = address;
                SetColor(address, Color.CYAN);
                AngryGhidraProvider.chckbxBlankState.setSelected(true);
               AngryGhidraProvider.TFBlankState.setText("0x" + address.toString());
            }
        };

        SetBlankState.setPopupMenuData(new MenuData(new String[] {
            MenuName,
            "Set",
            "Blank State Address"
        }, null, Group_Name));
        tool.addAction(SetBlankState);

        ListingContextAction UnSetBlankState = new ListingContextAction("Unset Blank State Address", getName()) {

            @Override
            protected void actionPerformed(ListingActionContext context) {

                Address address = context.getLocation().getAddress();
                UnSetColor(address);
                CurrentBlankAddr = null;
               AngryGhidraProvider.TFBlankState.setText("");
                AngryGhidraProvider.chckbxBlankState.setSelected(false);

            }
        };

        UnSetBlankState.setPopupMenuData(new MenuData(new String[] {
            MenuName,
            "Unset",
            "Blank State Address"
        }, null, Group_Name));
        tool.addAction(UnSetBlankState);

        ListingContextAction SetAvoid = new ListingContextAction("Set Avoid Address", getName()) {

            @Override
            protected void actionPerformed(ListingActionContext context) {

                Address address = context.getLocation().getAddress();
                SetColor(address, Color.RED);
                AngryGhidraProvider.chckbxAvoidAddresses.setSelected(true);
                if (AngryGhidraProvider.textArea.getText().isEmpty()) {
                    AngryGhidraProvider.textArea.setText("0x" + address.toString());
                } else {
                    AngryGhidraProvider.textArea.append("," + System.getProperty("line.separator") + "0x" + address.toString());
                }
                CurrentAvoidAddrses.add(address);
            }
        };

        SetAvoid.setPopupMenuData(new MenuData(new String[] {
            MenuName,
            "Set",
            "Avoid Address"
        }, null, Group_Name));
        tool.addAction(SetAvoid);

        ListingContextAction UnSetAvoid = new ListingContextAction("Unset Avoid Address", getName()) {

            @Override
            protected void actionPerformed(ListingActionContext context) {

                Address address = context.getLocation().getAddress();
                UnSetColor(address);
                String AvoidAreaText = AngryGhidraProvider.textArea.getText();
                int addrindex = AvoidAreaText.indexOf("0x" + address.toString());
                int commaindex = AvoidAreaText.indexOf(",");

                if (addrindex == 0 & commaindex != -1) {
                    AvoidAreaText = AvoidAreaText.replace("0x" + address.toString() + "," + System.getProperty("line.separator"), "");
                }
                if (addrindex == 0 & commaindex == -1) {
                    AvoidAreaText = AvoidAreaText.replace("0x" + address.toString(), "");
                }
                if (addrindex != 0) {
                    AvoidAreaText = AvoidAreaText.replace("," + System.getProperty("line.separator") + "0x" + address.toString(), "");
                }

                AngryGhidraProvider.textArea.setText(AvoidAreaText);
                CurrentAvoidAddrses.remove(address);

            }
        };

        UnSetAvoid.setPopupMenuData(new MenuData(new String[] {
            MenuName,
            "Unset",
            "Avoid Address"
        }, null, Group_Name));
        tool.addAction(UnSetAvoid); 
        
        ListingContextAction ApplyPatchedBytes = new ListingContextAction("Apply Patched Bytes", getName()) {

            @Override
            protected void actionPerformed(ListingActionContext context) {
                    
            	Address MinAddress = context.getSelection().getMinAddress();
                AddressIterator addressRange = context.getSelection().getAddresses(true);
                StringBuilder HexStringBuilder = new StringBuilder();
                for (Address address: addressRange) {
                	byte Byte = 0;
					try {
						Byte = context.getProgram().getMemory().getByte(address);
					} catch (MemoryAccessException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
                	HexStringBuilder.append(String.format("%02X", Byte));                	
                }  
                String HexValueString = HexStringBuilder.toString();                
                BigInteger HexValue = new BigInteger(HexValueString, 16);
                
                if (AngryGhidraProvider.TFstore_addr.getText().isEmpty() == false) {
                	
                	IntegerTextField TFaddr = new IntegerTextField();
                	TFaddr.setHexMode();
                	TFaddr.setValue(MinAddress.getOffset());
                    GridBagConstraints gbc_TFaddr = new GridBagConstraints();
                    gbc_TFaddr.fill = GridBagConstraints.HORIZONTAL;
                    gbc_TFaddr.anchor = GridBagConstraints.NORTH;
                    gbc_TFaddr.gridx = 1;
                    gbc_TFaddr.insets = new Insets(0, 0, 0, 5);
                    gbc_TFaddr.gridy = AngryGhidraProvider.GuiStoreCounter;
                    gbc_TFaddr.weightx = 1;
                    gbc_TFaddr.weighty = 0.1;
                    AngryGhidraProvider.WMPanel.add(TFaddr.getComponent(), gbc_TFaddr);                
                    AngryGhidraProvider.TFStoreAddrs.add(TFaddr);

                    IntegerTextField TFval = new IntegerTextField();
                    TFval.setHexMode();
                    TFval.setValue(HexValue);
                    GridBagConstraints gbc_TFval = new GridBagConstraints();
                    gbc_TFval.fill = GridBagConstraints.HORIZONTAL;
                    gbc_TFval.anchor = GridBagConstraints.NORTH;
                    gbc_TFval.insets = new Insets(0, 0, 0, 5);
                    gbc_TFval.gridx = 3;
                    gbc_TFval.gridy = AngryGhidraProvider.GuiStoreCounter;
                    gbc_TFval.weightx = 1;
                    gbc_TFval.weighty = 0.1;
                    AngryGhidraProvider.WMPanel.add(TFval.getComponent(), gbc_TFval);                
                    AngryGhidraProvider.TFStoreVals.add(TFval);

                    JButton btnDel = new JButton("");
                    btnDel.setBorder(null);
                    btnDel.setContentAreaFilled(false);
                    btnDel.setIcon(new ImageIcon(getClass().getResource("/images/edit-delete.png")));
                    GridBagConstraints gbc_btnDel = new GridBagConstraints();
                    gbc_btnDel.fill = GridBagConstraints.HORIZONTAL;
                    gbc_btnDel.anchor = GridBagConstraints.NORTH;
                    gbc_btnDel.insets = new Insets(0, 0, 0, 5);
                    gbc_btnDel.gridx = 0;
                    gbc_btnDel.gridy = AngryGhidraProvider.GuiStoreCounter++;
                    gbc_btnDel.weighty = 0.1;				
                    AngryGhidraProvider.WMPanel.add(btnDel, gbc_btnDel);
                    AngryGhidraProvider.delStore.add(btnDel);
                    btnDel.addActionListener(new ActionListener() {
                        public void actionPerformed(ActionEvent e) {
                        	AngryGhidraProvider.GuiStoreCounter--;
                        	AngryGhidraProvider.WMPanel.remove(TFaddr.getComponent());
                        	AngryGhidraProvider.WMPanel.remove(TFval.getComponent());
                        	AngryGhidraProvider.WMPanel.remove(btnDel);
                        	AngryGhidraProvider.delStore.remove(btnDel);
                        	AngryGhidraProvider.TFStoreAddrs.remove(TFaddr);
                        	AngryGhidraProvider.TFStoreVals.remove(TFval);
                        	AngryGhidraProvider.WMPanel.repaint();
                        	AngryGhidraProvider.WMPanel.revalidate();
                        }

                    });
                    AngryGhidraProvider.WMPanel.repaint();
                    AngryGhidraProvider.WMPanel.revalidate();
                }            
                else {
                	AngryGhidraProvider.TFstore_addr.setValue(MinAddress.getOffset());
                	AngryGhidraProvider.TFstore_val.setValue(HexValue);                	
                }
                
            }
        };   
        ApplyPatchedBytes.setPopupMenuData(new MenuData(new String[] {
                MenuName,
                "Apply Patched Bytes"}, null, Group_Name));
        tool.addAction(ApplyPatchedBytes);

    }

    public static void UnSetColor(Address address) {

        ColorizingService service = tool.getService(ColorizingService.class);
        int TransactionID = program.startTransaction("UnSetColor");
        service.clearBackgroundColor(address, address);
        program.endTransaction(TransactionID, true);

    }

    public static void SetColor(Address address, Color color) {

        ColorizingService service = tool.getService(ColorizingService.class);
        int TransactionID = program.startTransaction("SetColor");
        service.setBackgroundColor(address, address, color);
        program.endTransaction(TransactionID, true);

    }
    
}
