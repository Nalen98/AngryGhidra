/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package angryghidra;

import ghidra.app.ExamplesPluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;


/**
 * TODO: Provide class-level documentation that describes what this plugin does.
 */
//@formatter:off
@PluginInfo(
    status = PluginStatus.STABLE,
    packageName = ExamplesPluginPackage.NAME,
    category = PluginCategoryNames.ANALYSIS,
    shortDescription = "Use Angr from Ghidra.",
    description = "One click symbolic execution using Angr from Your Ghidra."
)
//@formatter:on
public class AngryGhidraPlugin extends ProgramPlugin {

    AngryGhidraProvider provider;
    Program program;
    AngryGhidraPopupMenu popup;        

    public AngryGhidraPlugin(PluginTool tool) {
        super(tool, true, true);       
        String pluginName = getName();
        provider = new AngryGhidraProvider(this, pluginName, this.getCurrentProgram());
        createActions();
    }

    @Override
    public void init() {
        super.init();
    }

    @Override
    protected void programActivated(Program p) {
        program = p;
        provider.setProgram(p);
        popup.setProgram(p);
    }

    private void createActions() {    	
        popup = new AngryGhidraPopupMenu(this, program);
    }
}