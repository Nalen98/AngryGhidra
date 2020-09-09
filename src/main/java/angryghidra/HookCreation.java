package angryghidra;

import java.awt.Dimension;
import java.awt.EventQueue;
import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Image;
import java.awt.Insets;
import java.awt.Toolkit;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import javax.swing.GroupLayout;
import javax.swing.GroupLayout.Alignment;
import javax.swing.ImageIcon;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextField;
import javax.swing.LayoutStyle.ComponentPlacement;
import javax.swing.SwingConstants;

import docking.widgets.textfield.IntegerTextField;

public class HookCreation {

	static JFrame Hookframe;
	static IntegerTextField TFAddress;
	static JTextField TFHookReg1;
	static JTextField TFHookVal1;
	private int GuiHookRegCounter;
	private ArrayList < JTextField > TFregs;
    private ArrayList < JTextField > TFVals;
    private ArrayList < JButton > delButtons;   
    private IntegerTextField TFLength;

	public void main() {
		EventQueue.invokeLater(new Runnable() {
			public void run() {
				try {
					HookCreation window = new HookCreation();
					window.Hookframe.setVisible(true);
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		});
	}
	
	public HookCreation() {
		initialize();
	}
	
	private void initialize() {
		Hookframe = new JFrame();
		Hookframe.getContentPane().setMinimumSize(new Dimension(500, 333));
		Hookframe.setTitle("Add hook");		
		Hookframe.setMinimumSize(new Dimension(500, 333));		
		Hookframe.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
		Hookframe.setLocationRelativeTo(null);
		Image icon = Toolkit.getDefaultToolkit().getImage(getClass().getResource("/images/Ico.png"));
		Hookframe.setIconImage(icon);		
		
		ImageIcon Addicon = new ImageIcon(getClass().getResource("/images/add.png"));
		delButtons = new ArrayList < JButton > ();
		TFregs = new ArrayList < JTextField > ();
        	TFVals = new ArrayList < JTextField > ();
		GuiHookRegCounter = 2;
		
		TFAddress = new IntegerTextField();		
		TFAddress.setHexMode();
		GridBagConstraints gbc_TFAddress = new GridBagConstraints();
		gbc_TFAddress.anchor = GridBagConstraints.NORTH;
		gbc_TFAddress.fill = GridBagConstraints.HORIZONTAL;
		gbc_TFAddress.gridx = 0;
		gbc_TFAddress.gridy = 1;
		
		JButton btnCreate = new JButton("Add");
		btnCreate.setFont(new Font("SansSerif", Font.PLAIN, 12));
		btnCreate.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				
				if (TFAddress.getText().isEmpty() == false & TFLength.getText().isEmpty() == false) {										
					String[] options = new String[2];
					options[0] = TFAddress.getText();
					options[1] = TFLength.getText();
					String[][] Regs = new String[2][TFregs.size()+1];					
					 if (TFHookReg1.getText().isEmpty() == false & TFHookVal1.getText().isEmpty() == false & (TFHookVal1.getText().matches("0x[0-9A-Fa-f]+") == true || 
						TFHookVal1.getText().matches("[0-9]+") == true || TFHookVal1.getText().contains("sv"))) {	                        
						 	Regs[0][0] = TFHookReg1.getText();
						 	Regs[1][0] = TFHookVal1.getText();	                       
	                        for (int i = 0; i < TFregs.size(); i++) { 
	                        	if (TFregs.get(i).getText().isEmpty() == false & TFVals.get(i).getText().isEmpty() == false & (TFVals.get(i).getText().matches("0x[0-9A-Fa-f]+") == true || 
	                            	TFVals.get(i).getText().matches("[0-9]+") == true || TFVals.get(i).getText().contains("sv"))) {	                        		
	                        		Regs[0][i+1] = TFregs.get(i).getText();
	                        		Regs[1][i+1] = TFVals.get(i).getText();
	                        	}
	                         }		                        
	    			AngryGhidraProvider.Hook.put(options, Regs); 	    					
	    			JLabel lbHook = new JLabel("Hook at " + TFAddress.getText());	    					
	    			lbHook.setFont(new Font("SansSerif", Font.PLAIN, 12)); 
	    	                GridBagConstraints gbc_lbHook = new GridBagConstraints();
	    	                gbc_lbHook.fill = GridBagConstraints.HORIZONTAL;
	    	                gbc_lbHook.anchor = GridBagConstraints.CENTER;
	    	                gbc_lbHook.gridwidth = 3;
	    	                gbc_lbHook.gridx = 1;
	    	                gbc_lbHook.insets = new Insets(0, 0, 0, 5);
	    	                gbc_lbHook.gridy = AngryGhidraProvider.GuiHookCounter;
	    	                gbc_lbHook.weightx = 1;
	    	                gbc_lbHook.weighty = 0.1;
	    	                AngryGhidraProvider.RegHookPanel.add(lbHook, gbc_lbHook);     					
	    					
	    			 JButton btnDel = new JButton("");
	    		         btnDel.setBorder(null);
	    		         btnDel.setContentAreaFilled(false);
	    		         btnDel.setIcon(new ImageIcon(getClass().getResource("/images/edit-delete.png")));
	    		         GridBagConstraints gbc_btnDel = new GridBagConstraints();
	    		         gbc_btnDel.insets = new Insets(0, 0, 0, 5);
	    		         gbc_btnDel.fill = GridBagConstraints.HORIZONTAL;
	    		         gbc_btnDel.anchor = GridBagConstraints.CENTER;
	    		         gbc_btnDel.gridx = 0;
	    		         gbc_btnDel.gridy =  AngryGhidraProvider.GuiHookCounter++;
	    		         gbc_btnDel.weighty = 0.1;				
	    		         AngryGhidraProvider.RegHookPanel.add(btnDel, gbc_btnDel);
	    		         AngryGhidraProvider.delHooks.add(btnDel);
	    		         btnDel.addActionListener(new ActionListener() {
	    	                    public void actionPerformed(ActionEvent e) {
					AngryGhidraProvider.Hook.remove(options, Regs);
	    	                    	AngryGhidraProvider.GuiHookCounter--;
	    	                    	AngryGhidraProvider.RegHookPanel.remove(lbHook);
	    	                    	AngryGhidraProvider.RegHookPanel.remove(btnDel);
	    	                    	AngryGhidraProvider.delHooks.remove(btnDel);
	    	                    	AngryGhidraProvider.lbHooks.remove(lbHook);
	    	                        AngryGhidraProvider.RegHookPanel.repaint();
	    	                        AngryGhidraProvider.RegHookPanel.revalidate();
	    	                    }
	    	                });
	    		            AngryGhidraProvider.RegHookPanel.repaint();
	                        AngryGhidraProvider.RegHookPanel.revalidate();	    	                
	                    }
			}				
		     }
		});		
		
	JLabel lbRegisters = new JLabel("<html>Registers<br/>Hint: to create and store symbolic vector enter \"sv{length}\", for example \"sv16\"</html>");
	lbRegisters.setHorizontalAlignment(SwingConstants.CENTER);
	lbRegisters.setFont(new Font("SansSerif", Font.PLAIN, 12));
		
	JPanel RegPanel = new JPanel();
	GridBagLayout gbl_RegPanel = new GridBagLayout();
	gbl_RegPanel.columnWidths = new int[]{0, 0, 0, 0, 0, 0};
	gbl_RegPanel.rowHeights = new int[]{0, 0, 0};
	gbl_RegPanel.columnWeights = new double[]{0.0, 0.0, 0.0, 0.0, 0.0, Double.MIN_VALUE};
	gbl_RegPanel.rowWeights = new double[]{0.0, 0.0, Double.MIN_VALUE};
	RegPanel.setLayout(gbl_RegPanel);
		
	JLabel lblReg = new JLabel("Register");
        lblReg.setFont(new Font("SansSerif", Font.PLAIN, 12));
        GridBagConstraints gbc_lblReg = new GridBagConstraints();
        gbc_lblReg.anchor = GridBagConstraints.SOUTH;
        gbc_lblReg.insets = new Insets(0, 0, 0, 5);
        gbc_lblReg.gridx = 1;
        gbc_lblReg.gridy = 0;
        gbc_lblReg.weightx = 1;        
        RegPanel.add(lblReg, gbc_lblReg);

        JLabel lblValue = new JLabel("Value");
        lblValue.setFont(new Font("SansSerif", Font.PLAIN, 12));
        GridBagConstraints gbc_lblValue = new GridBagConstraints();
        gbc_lblValue.anchor = GridBagConstraints.SOUTH;
        gbc_lblValue.insets = new Insets(0, 0, 0, 5);
        gbc_lblValue.gridx = 3;
        gbc_lblValue.gridy = 0;
        gbc_lblValue.weightx = 1;        
        RegPanel.add(lblValue, gbc_lblValue);

        JButton btnAddButton = new JButton("");
        GridBagConstraints gbc_btnAddButton = new GridBagConstraints();
        gbc_btnAddButton.anchor = GridBagConstraints.NORTH;
        gbc_btnAddButton.fill = GridBagConstraints.HORIZONTAL;
        gbc_btnAddButton.insets = new Insets(0, 0, 0, 5);
        gbc_btnAddButton.gridx = 0;
        gbc_btnAddButton.gridy = 1;
        gbc_btnAddButton.weighty = 0.1;
        RegPanel.add(btnAddButton, gbc_btnAddButton);
        btnAddButton.setBorder(null);
        btnAddButton.setContentAreaFilled(false);
        btnAddButton.setIcon(Addicon);

        TFHookReg1 = new JTextField();
        TFHookReg1.setBorder(TFAddress.getComponent().getBorder());
        GridBagConstraints gbc_TFReg1 = new GridBagConstraints();
        gbc_TFReg1.anchor = GridBagConstraints.NORTH;
        gbc_TFReg1.fill = GridBagConstraints.HORIZONTAL;
        gbc_TFReg1.insets = new Insets(0, 0, 0, 5);
        gbc_TFReg1.gridx = 1;
        gbc_TFReg1.gridy = 1;
        gbc_TFReg1.weighty = 0.1;
        RegPanel.add(TFHookReg1, gbc_TFReg1);        
        TFHookReg1.setBorder(TFAddress.getComponent().getBorder());
        
        TFHookVal1 = new JTextField();       
        TFHookVal1.setBorder(TFAddress.getComponent().getBorder());
        GridBagConstraints gbc_TFVal1 = new GridBagConstraints();
        gbc_TFVal1.insets = new Insets(0, 0, 0, 5);
        gbc_TFVal1.anchor = GridBagConstraints.NORTH;
        gbc_TFVal1.fill = GridBagConstraints.HORIZONTAL;
        gbc_TFVal1.gridx = 3;
        gbc_TFVal1.gridy = 1;
        gbc_TFVal1.weightx = 1;
        gbc_TFVal1.weighty = 0.1;
        RegPanel.add(TFHookVal1, gbc_TFVal1);         
        
        btnAddButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
               
                JTextField TFReg = new JTextField();
                TFReg.setBorder(TFAddress.getComponent().getBorder());
                GridBagConstraints gbc_TFReg = new GridBagConstraints();
                gbc_TFReg.fill = GridBagConstraints.HORIZONTAL;
                gbc_TFReg.anchor = GridBagConstraints.NORTH;
                gbc_TFReg.gridx = 1;
                gbc_TFReg.insets = new Insets(0, 0, 0, 5);
                gbc_TFReg.gridy = GuiHookRegCounter;
                gbc_TFReg.weightx = 1;
                gbc_TFReg.weighty = 0.1;
                RegPanel.add(TFReg, gbc_TFReg);                              
                TFregs.add(TFReg);

                JTextField TFVal = new JTextField();
                TFVal.setBorder(TFAddress.getComponent().getBorder());
                GridBagConstraints gbc_TFVal = new GridBagConstraints();
                gbc_TFVal.fill = GridBagConstraints.HORIZONTAL;
                gbc_TFVal.anchor = GridBagConstraints.NORTH;
                gbc_TFVal.insets = new Insets(0, 0, 0, 5);
                gbc_TFVal.gridx = 3;
                gbc_TFVal.gridy = GuiHookRegCounter;
                gbc_TFVal.weightx = 1;
                gbc_TFVal.weighty = 0.1;
                RegPanel.add(TFVal, gbc_TFVal);               
                TFVals.add(TFVal);

                JButton btnDel = new JButton("");
                btnDel.setBorder(null);
                btnDel.setContentAreaFilled(false);
                btnDel.setIcon(new ImageIcon(getClass().getResource("/images/edit-delete.png")));
                GridBagConstraints gbc_btnDel = new GridBagConstraints();
                gbc_btnDel.insets = new Insets(0, 0, 0, 5);
                gbc_btnDel.fill = GridBagConstraints.HORIZONTAL;
                gbc_btnDel.anchor = GridBagConstraints.NORTH;
                gbc_btnDel.gridx = 0;
                gbc_btnDel.gridy = GuiHookRegCounter++;
                gbc_btnDel.weighty = 0.1;				
                RegPanel.add(btnDel, gbc_btnDel);
                delButtons.add(btnDel);
                btnDel.addActionListener(new ActionListener() {
                    public void actionPerformed(ActionEvent e) {                    	
                    	GuiHookRegCounter--;
                        RegPanel.remove(TFReg);
                        RegPanel.remove(TFVal);
                        RegPanel.remove(btnDel);
                        delButtons.remove(btnDel);
                        TFregs.remove(TFReg);
                        TFVals.remove(TFVal);
                        RegPanel.repaint();
                        RegPanel.revalidate();
                    }

                });
                
                RegPanel.repaint();
                RegPanel.revalidate();
            }
        });		
		JPanel AddrPanel = new JPanel();
		
		GroupLayout groupLayout = new GroupLayout(Hookframe.getContentPane());
		groupLayout.setHorizontalGroup(
			groupLayout.createParallelGroup(Alignment.TRAILING)
				.addGroup(groupLayout.createSequentialGroup()
					.addGap(18)
					.addComponent(AddrPanel, GroupLayout.DEFAULT_SIZE, 129, Short.MAX_VALUE)
					.addGap(39)
					.addGroup(groupLayout.createParallelGroup(Alignment.LEADING)
						.addComponent(RegPanel, GroupLayout.DEFAULT_SIZE, 238, Short.MAX_VALUE)
						.addComponent(lbRegisters, GroupLayout.DEFAULT_SIZE, 238, Short.MAX_VALUE))
					.addContainerGap())
				.addGroup(groupLayout.createSequentialGroup()
					.addGap(129)
					.addComponent(btnCreate, GroupLayout.DEFAULT_SIZE, 184, Short.MAX_VALUE)
					.addGap(121))
		);
		groupLayout.setVerticalGroup(
			groupLayout.createParallelGroup(Alignment.LEADING)
				.addGroup(groupLayout.createSequentialGroup()
					.addGap(20)
					.addGroup(groupLayout.createParallelGroup(Alignment.LEADING, false)
						.addGroup(groupLayout.createSequentialGroup()
							.addComponent(lbRegisters, GroupLayout.PREFERRED_SIZE, 47, GroupLayout.PREFERRED_SIZE)
							.addPreferredGap(ComponentPlacement.UNRELATED)
							.addComponent(RegPanel, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE))
						.addComponent(AddrPanel, 0, 0, Short.MAX_VALUE))
					.addPreferredGap(ComponentPlacement.RELATED, 130, Short.MAX_VALUE)
					.addComponent(btnCreate)
					.addGap(27))
		);
		GridBagLayout gbl_AddrPanel = new GridBagLayout();
		gbl_AddrPanel.columnWidths = new int[]{0, 0};
		gbl_AddrPanel.rowHeights = new int[]{0, 0, 0, 0, 0};
		gbl_AddrPanel.columnWeights = new double[]{1.0, Double.MIN_VALUE};
		gbl_AddrPanel.rowWeights = new double[]{0.0, 0.0, 0.0, 0.0, Double.MIN_VALUE};
		AddrPanel.setLayout(gbl_AddrPanel);
		
		JLabel lbAddress = new JLabel("Hook at address:");
		lbAddress.setFont(new Font("SansSerif", Font.PLAIN, 12));
		GridBagConstraints gbc_lbAddress = new GridBagConstraints();
		gbc_lbAddress.anchor = GridBagConstraints.SOUTH;
		gbc_lbAddress.insets = new Insets(0, 0, 5, 5);
		gbc_lbAddress.gridx = 0;
		gbc_lbAddress.gridy = 0;
		AddrPanel.add(lbAddress, gbc_lbAddress);
		
		TFAddress = new IntegerTextField();
		TFAddress.setHexMode();
		GridBagConstraints gbc_AddrPanel = new GridBagConstraints();
		gbc_AddrPanel.fill = GridBagConstraints.HORIZONTAL;
		gbc_AddrPanel.gridx = 0;
		gbc_AddrPanel.gridy = 1;
		AddrPanel.add(TFAddress.getComponent(), gbc_AddrPanel);			
		
		JLabel lblHookLength = new JLabel("Hook length");
		lblHookLength.setFont(new Font("SansSerif", Font.PLAIN, 12));
		GridBagConstraints gbc_lblHookLength = new GridBagConstraints();
		gbc_lblHookLength.anchor = GridBagConstraints.SOUTH;
		gbc_lblHookLength.insets = new Insets(0, 0, 5, 5);
		gbc_lblHookLength.gridx = 0;
		gbc_lblHookLength.gridy = 2;
		AddrPanel.add(lblHookLength, gbc_lblHookLength);
		
		TFLength = new IntegerTextField();
		TFLength.setDecimalMode();
		GridBagConstraints gbc_TFLength = new GridBagConstraints();
		gbc_TFLength.fill = GridBagConstraints.HORIZONTAL;
		gbc_TFLength.gridx = 0;
		gbc_TFLength.gridy = 3;
		AddrPanel.add(TFLength.getComponent(), gbc_TFLength);		
		Hookframe.getContentPane().setLayout(groupLayout);
	}
}
