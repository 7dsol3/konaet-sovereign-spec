function konaet_ecosystem_visual(output,x,probability,report)
%KONAET_ECOSYSTEM_VISUAL Recorded execution trace, rendered entirely in MATLAB.
bg=[0.025 0.018 0.065]; violet=[0.67 0.34 1]; cyan=[0.22 0.88 0.91]; white=[0.93 0.92 1];
f=figure('Visible','off','Color',bg,'Position',[50 50 1440 800]); cleanup=onCleanup(@() close(f)); %#ok<NASGU>
ax=axes(f,'Position',[0 0 1 1],'Color',bg); axis(ax,[0 1440 0 800]); axis(ax,'off'); hold(ax,'on');
text(ax,70,730,'K O N A E T','FontSize',34,'Color',white,'FontWeight','bold','FontName','DejaVu Sans');
text(ax,72,685,'THREE SOURCES / ONE VERIFIABLE TRACE','FontSize',13,'Color',cyan,'FontName','DejaVu Sans');
labels={'REALIDADE QUANTICA','KONAET','SOVEREIGN .KO'};
sub={'MATLAB / wave packet','Git contracts / activation','Commitment / quorum receipt'};
for j=1:3
    rectangle(ax,'Position',[70+(j-1)*450 425 400 180],'FaceColor',[0.065 0.045 0.13], ...
        'EdgeColor',violet,'LineWidth',1.3,'Curvature',0.08);
    text(ax,95+(j-1)*450,560,sprintf('0%d',j),'FontSize',13,'Color',cyan);
    text(ax,95+(j-1)*450,515,labels{j},'FontSize',18,'Color',white,'FontWeight','bold','Interpreter','none');
    text(ax,95+(j-1)*450,475,sub{j},'FontSize',11,'Color',[0.72 0.68 0.86],'Interpreter','none');
end
plot(ax,[270 1170],[390 390],'-','Color',violet,'LineWidth',2);
for j=1:3, plot(ax,270+(j-1)*450,390,'o','Color',cyan,'MarkerFaceColor',bg,'MarkerSize',9,'LineWidth',2); end
text(ax,75,325,sprintf('%d BYTE / PROVENANCE CHECKS  +  %d GIT CONTRACTS  +  %d ACTIVATION CHECKS', ...
    report.checksPassed,report.botContracts,report.botActivation),'FontSize',13,'Color',white);
text(ax,75,95,'RECORDED EXECUTION / MATLAB RENDER / NOT LIVE TELEMETRY','FontSize',11,'Color',cyan);
text(ax,75,60,['SOURCE  ' report.sources.sovereign(1:12) '    /    NO PHYSICAL OR GENERAL-SUPERIORITY CLAIM'], ...
    'FontSize',10,'Color',[0.65 0.61 0.77],'Interpreter','none');
curve=plot(ax,750+12*x,150+800*probability,'Color',violet,'LineWidth',2);
dot=plot(ax,270,390,'o','Color',cyan,'MarkerFaceColor',cyan,'MarkerSize',12);
for k=1:24
    phase=(k-1)/24; set(dot,'XData',270+900*phase);
    set(curve,'YData',150+800*circshift(probability,round(phase*60)));
    drawnow;
    rgb=print(f,'-RGBImage','-r100'); [indices,map]=rgb2ind(rgb,192);
    file=fullfile(output,'konaet-ecosystem.gif');
    if k==1
        imwrite(rgb,fullfile(output,'konaet-ecosystem.png'));
        imwrite(indices,map,file,'gif','LoopCount',inf,'DelayTime',0.14);
    else, imwrite(indices,map,file,'gif','WriteMode','append','DelayTime',0.14); end
end
end
