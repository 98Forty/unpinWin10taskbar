#ifndef COINCONTROL_H
#define COINCONTROL_H

/** Coin Control Features. */
class CCoinControl
{
public:
    CTxDestination destChange;

    CCoinControl()
    {
        SetNull();
    }
        
    void SetNull()
    {
        destChange = CNoDestination();
        setSelected.clear();
    }
    
    bool HasSelected() const
    {
        retu